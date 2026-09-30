use super::*;
use crate::cov::active::{LiveCovSelection, LiveDeviceCov};
use crate::device_view::{DeviceExecution, DeviceReadContext};
use bacnet_services::read_property::ReadPropertyRequest;
use bacnet_types::error::ErrorDetail;

/// ReadProperty under the narrow responder's execution profile, within the responder's
/// configured read work limit.
pub(super) async fn read_property_response(
    db: &RwLock<ObjectDatabase>,
    request: &ConfirmedRequestPdu,
    execution: DeviceExecution,
    registered_port: Option<ObjectIdentifier>,
    work_limit: usize,
    identity: Option<&bacnet_objects::DeviceIdentity>,
) -> Apdu {
    read_property_response_observed(
        db,
        None,
        ReadProfile {
            execution,
            registered_port,
            work_limit,
            identity,
        },
        request,
        |_, _, _, _| {},
    )
    .await
}

/// The server tables a read samples the selected Device's server-owned lists
/// from: the COV table for its COV lists, the binding table for its
/// Device_Address_Binding (#1369).
#[derive(Clone, Copy)]
pub(in crate::server) struct LiveTables<'a> {
    pub(in crate::server) cov: &'a RwLock<CovSubscriptionTable>,
    pub(in crate::server) bindings: &'a RwLock<DeviceBindingTable>,
}

/// Request-local live Device `Active_COV_Subscriptions`,
/// `Active_COV_Multiple_Subscriptions` and `Device_Address_Binding` (Clause
/// 12.11), as selected.
///
/// Lock order is database, then COV table, then binding table: the caller
/// holds the database read guard; each table's read guard is held only to
/// copy what is live at one instant, and is released before the next is
/// taken and before any object read or encoding. A request that selects
/// neither COV list doesn't touch the COV table.
pub(in crate::server) async fn active_cov_snapshot(
    db: &ObjectDatabase,
    tables: LiveTables<'_>,
    selection: LiveCovSelection,
) -> LiveDeviceCov {
    let live = if selection.reads_cov() {
        let entries = {
            let table = tables.cov.read().await;
            table.live_cov_entries(selection, runtime_clock::now())
        };
        LiveDeviceCov::project(db, selection, entries)
    } else {
        LiveDeviceCov::default()
    };
    let bindings = address_bindings(tables.bindings, selection).await;
    live.with_address_bindings(selection, bindings)
}

/// The selected Device's Device_Address_Binding, when `selection` reads it:
/// the bindings `table` holds now, copied under its read guard (#1369).
pub(in crate::server) async fn address_bindings(
    table: &RwLock<DeviceBindingTable>,
    selection: LiveCovSelection,
) -> Option<PropertyValue> {
    if !selection.address_bindings {
        return None;
    }
    let table = table.read().await;
    Some(table.address_binding_list(runtime_clock::now()))
}

/// Budgeted ReadPropertyMultiple under one database read guard. The request
/// is planned first; when the plan reads one of the Device's server-owned
/// lists, one request-local projection serves every such row, a Group's
/// member rows included (#1171, #1213). A request past its work limit fails
/// in planning, before any table is sampled.
pub(super) async fn read_property_multiple_observed(
    db: &RwLock<ObjectDatabase>,
    tables: LiveTables<'_>,
    service_request: &[u8],
    service_ack: &mut BytesMut,
    config: &ServerConfig,
    mut completed: impl FnMut(
        &ObjectDatabase,
        ObjectIdentifier,
        PropertyIdentifier,
        Option<u32>,
        Option<(ErrorClass, ErrorCode)>,
    ),
) -> Result<(), handlers::ReadFailure> {
    let db = db.read().await;
    let request = bacnet_services::rpm::ReadPropertyMultipleRequest::decode(service_request)
        .map_err(|error| handlers::ReadFailure::Service(error.into_request_reject()))?;
    let budget = config.read_property_multiple_budget;
    let view = DeviceReadContext::new(&db, DeviceExecution::FullServer)
        .with_identity(Some(&config.device))
        .with_registered_port(config.registered_network_port);
    let plan = handlers::RpmPlan::new(&db, &request, budget.max_result_elements, Some(&view))?;
    let live = match plan.live_cov(&db) {
        Some(selection) => Some(active_cov_snapshot(&db, tables, selection).await),
        None => None,
    };
    let view = view.with_live(live.as_ref());
    plan.read_observed(
        &db,
        Some(&view),
        service_ack,
        budget.max_service_ack_bytes,
        |oid, property, index, result| completed(&db, oid, property, index, result),
    )
}

/// Runtime declarations and work limits for one Device property read.
pub(super) struct ReadProfile<'a> {
    pub(super) execution: DeviceExecution,
    pub(super) registered_port: Option<ObjectIdentifier>,
    pub(super) work_limit: usize,
    pub(super) identity: Option<&'a bacnet_objects::DeviceIdentity>,
}

/// ReadPropertyMultiple under the narrow responder's execution profile, within `budget`. The
/// responder keeps no COV subscriptions, so no live COV projection is read.
pub(super) async fn read_property_multiple_response(
    db: &RwLock<ObjectDatabase>,
    request: &ConfirmedRequestPdu,
    execution: DeviceExecution,
    registered_port: Option<ObjectIdentifier>,
    identity: Option<&bacnet_objects::DeviceIdentity>,
    budget: crate::server::ReadPropertyMultipleBudget,
) -> Apdu {
    let invoke_id = request.invoke_id;
    let service_choice = request.service_choice;
    let mut service_ack = BytesMut::with_capacity(512);
    let db = db.read().await;
    let result =
        bacnet_services::rpm::ReadPropertyMultipleRequest::decode(&request.service_request)
            .map_err(|error| handlers::ReadFailure::Service(error.into_request_reject()))
            .and_then(|decoded| {
                let view = DeviceReadContext::new(&db, execution)
                    .with_identity(identity)
                    .with_registered_port(registered_port);
                handlers::RpmPlan::new(&db, &decoded, budget.max_result_elements, Some(&view))?
                    .read_observed(
                        &db,
                        Some(&view),
                        &mut service_ack,
                        budget.max_service_ack_bytes,
                        |_, _, _, _| {},
                    )
            });
    match result {
        Ok(()) => Apdu::ComplexAck(ComplexAck {
            segmented: false,
            more_follows: false,
            invoke_id,
            sequence_number: None,
            proposed_window_size: None,
            service_choice,
            service_ack: service_ack.freeze(),
        }),
        Err(handlers::ReadFailure::Service(error)) => {
            error_apdu_from_error(invoke_id, service_choice, &error)
        }
        Err(handlers::ReadFailure::Work) => Apdu::Abort(AbortPdu {
            sent_by_server: true,
            invoke_id,
            abort_reason: AbortReason::OUT_OF_RESOURCES,
        }),
        Err(handlers::ReadFailure::Bytes) => Apdu::Abort(AbortPdu {
            sent_by_server: true,
            invoke_id,
            abort_reason: AbortReason::BUFFER_OVERFLOW,
        }),
    }
}

/// ReadProperty under one database read guard, planned before any table is
/// sampled (#1213). A Group's Present_Value counts against `work_limit` as
/// a ReadPropertyMultiple naming only it would, and a read past it is aborted
/// as that request would be.
pub(super) async fn read_property_response_observed(
    db: &RwLock<ObjectDatabase>,
    tables: Option<LiveTables<'_>>,
    profile: ReadProfile<'_>,
    request: &ConfirmedRequestPdu,
    mut completed: impl FnMut(
        &ObjectDatabase,
        ObjectIdentifier,
        &ReadPropertyRequest,
        &Result<(), Error>,
    ),
) -> Apdu {
    let mut service_ack = BytesMut::with_capacity(512);
    let db = db.read().await;
    let result = match ReadPropertyRequest::decode(&request.service_request)
        .map_err(Error::into_request_reject)
    {
        Ok(decoded) => {
            let view = DeviceReadContext::new(&db, profile.execution)
                .with_identity(profile.identity)
                .with_registered_port(profile.registered_port)
                .with_work_limit(profile.work_limit);
            let lookup_oid = handlers::resolve_read_target(
                &db,
                &decoded.object_identifier,
                profile.registered_port,
                view.device_oid(),
            );
            match handlers::plan_read_property(
                &db,
                Some(&view),
                lookup_oid,
                decoded.property_identifier,
                decoded.property_array_index,
            ) {
                Ok(plan) => {
                    let live = match (tables, plan.live_cov(&db)) {
                        (Some(tables), Some(selection)) => {
                            Some(active_cov_snapshot(&db, tables, selection).await)
                        }
                        _ => None,
                    };
                    let view = view.with_live(live.as_ref());
                    handlers::read_property_request_observed(
                        &db,
                        Some(&view),
                        &decoded,
                        plan,
                        &mut service_ack,
                        |oid, request, result| completed(&db, oid, request, result),
                    )
                    .map_err(handlers::ReadFailure::Service)
                }
                Err(failure) => Err(failure),
            }
        }
        Err(error) => Err(handlers::ReadFailure::Service(error)),
    };
    match result {
        Ok(()) => Apdu::ComplexAck(ComplexAck {
            segmented: false,
            more_follows: false,
            invoke_id: request.invoke_id,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: request.service_choice,
            service_ack: service_ack.freeze(),
        }),
        Err(handlers::ReadFailure::Service(error)) => {
            error_apdu_from_error(request.invoke_id, request.service_choice, &error)
        }
        // A Group's Present_Value past the work limit draws the abort an RPM
        // over its work budget does; ReadProperty has no byte budget.
        Err(handlers::ReadFailure::Work | handlers::ReadFailure::Bytes) => Apdu::Abort(AbortPdu {
            sent_by_server: true,
            invoke_id: request.invoke_id,
            abort_reason: AbortReason::OUT_OF_RESOURCES,
        }),
    }
}

/// The reply to a confirmed request `error` refused.
///
/// An [`Error::Reject`] draws a Reject PDU with its reason, for every
/// service, the formal-error ones included: a Reject has no
/// service-specific body. Each handler turns the error from decoding the
/// request into one with [`Error::into_request_reject`], so a syntax fault
/// in the request draws the Reject naming it (Clauses 18.9 and 20.1.8,
/// #1446). Any other refusal is an Error PDU, in the formal Clause 21
/// production for the services that have one; that includes a decoding
/// error met once the service is running, which is no syntax fault of the
/// request.
pub(in crate::server) fn error_apdu_from_error(
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    error: &Error,
) -> Apdu {
    if let Error::Reject { reason } = error {
        return Apdu::Reject(RejectPdu {
            invoke_id,
            reject_reason: *reason,
        });
    }
    let (error_class, error_code) = error_fields(error);
    let detail = match error {
        Error::Structured { detail, .. } => Some(detail.as_ref()),
        _ => None,
    };
    // Only an element refusal names an element; a refusal of the request or
    // its target (authorization, object, property, index, list-ness, an
    // object the server cannot create) carries zero (Clauses 15.1.1.3.1,
    // 15.2.1.3.1 and 15.3.1.3).
    let first_failed_element_number = match detail {
        Some(ErrorDetail::FirstFailedElementNumber(number)) => *number,
        _ => 0,
    };
    // These services answer every error with their Clause 21 production.
    if service_choice == ConfirmedServiceChoice::ADD_LIST_ELEMENT
        || service_choice == ConfirmedServiceChoice::REMOVE_LIST_ELEMENT
    {
        return Apdu::Error(
            bacnet_services::list_manipulation::ChangeListError {
                error_class,
                error_code,
                first_failed_element_number,
            }
            .to_error_pdu(invoke_id, service_choice),
        );
    }
    if service_choice == ConfirmedServiceChoice::CREATE_OBJECT {
        return Apdu::Error(
            bacnet_services::object_mgmt::CreateObjectError {
                error_class,
                error_code,
                first_failed_element_number,
            }
            .to_error_pdu(invoke_id),
        );
    }
    if service_choice == ConfirmedServiceChoice::SUBSCRIBE_COV_PROPERTY_MULTIPLE {
        // A refusal of one COV reference names it; any failure before the
        // references are processed is the general choice (Clause 13.16.2).
        let first_failed_subscription = match detail {
            Some(ErrorDetail::FirstFailedSubscription(reference)) => Some(reference.clone()),
            _ => None,
        };
        return Apdu::Error(
            bacnet_services::cov_multiple::SubscribeCOVPropertyMultipleError {
                error_class,
                error_code,
                first_failed_subscription,
            }
            .to_error_pdu(invoke_id),
        );
    }
    Apdu::Error(ErrorPdu {
        invoke_id,
        service_choice,
        error_class,
        error_code,
        error_data: Bytes::new(),
    })
}

pub(in crate::server) fn error_fields(error: &Error) -> (ErrorClass, ErrorCode) {
    match error {
        Error::Protocol { class, code } | Error::Structured { class, code, .. } => (*class, *code),
        _ => (ErrorClass::SERVICES, ErrorCode::OTHER),
    }
}

/// Send an encoded unsegmented response APDU, handing it off on an MS/TP
/// reply channel when one waits for it. Returns whether the response was
/// handed off: taken by the reply channel, or accepted by the transport.
pub(in crate::server) async fn send_unsegmented_response<T: TransportPort + 'static>(
    network: &NetworkLayer<T>,
    apdu: BytesMut,
    target: ResponseTarget<'_>,
    reply_tx: Option<tokio::sync::oneshot::Sender<Bytes>>,
    pending: Option<PendingConfirmedRequest>,
) -> bool {
    send_response(network, apdu, target, reply_tx, true, pending).await
}

/// `response` encoded, in a buffer sized for it.
pub(in crate::server) fn encoded_apdu(response: &Apdu) -> BytesMut {
    // Five octets cover every APDU header; a ComplexAck adds its service ACK.
    let body = match response {
        Apdu::ComplexAck(ack) => ack.service_ack.len(),
        _ => 0,
    };
    let mut buf = BytesMut::with_capacity(8 + body);
    encode_apdu(&mut buf, response).expect("valid APDU encoding");
    buf
}

/// Overload work shares the identical wire path without per-rejection error
/// logging. Admission/fallback telemetry is bounded and does not imply send success.
pub(in crate::server) async fn send_overload_response<T: TransportPort + 'static>(
    network: &NetworkLayer<T>,
    response: &Apdu,
    source_mac: &[u8],
    source_network: Option<&NpduAddress>,
    route: &bacnet_network::response_route::ResponseRoute,
    reply_tx: Option<tokio::sync::oneshot::Sender<Bytes>>,
) {
    send_response(
        network,
        encoded_apdu(response),
        ResponseTarget {
            source_mac,
            source_network,
            route,
        },
        reply_tx,
        false,
        None,
    )
    .await;
}

/// Resend already-encoded LSO response bytes without re-execution.
///
/// Replay path only: no mutation, no authorizer re-invocation, no COV/event
/// re-fire. Bytes are the exact APDU encoding stored at first-execution
/// response time (same invoke echo); the NPDU wrap / transport send mirrors
/// [`send_unsegmented_response`] so the wire image is byte-identical.
pub(in crate::server) async fn send_replay_bytes<T: TransportPort + 'static>(
    network: &NetworkLayer<T>,
    apdu_bytes: &Bytes,
    source_mac: &[u8],
    source_network: Option<&NpduAddress>,
    route: &bacnet_network::response_route::ResponseRoute,
    reply_tx: Option<tokio::sync::oneshot::Sender<Bytes>>,
) {
    send_raw_response(
        network,
        apdu_bytes,
        source_mac,
        source_network,
        route,
        reply_tx,
    )
    .await;
}

async fn send_raw_response<T: TransportPort + 'static>(
    network: &NetworkLayer<T>,
    apdu_bytes: &Bytes,
    source_mac: &[u8],
    source_network: Option<&NpduAddress>,
    route: &bacnet_network::response_route::ResponseRoute,
    reply_tx: Option<tokio::sync::oneshot::Sender<Bytes>>,
) {
    let reply_tx = if route.requires_direct_response() {
        None
    } else {
        reply_tx
    };
    if let Some(tx) = reply_tx {
        match network.encode_response_for_handoff(
            bacnet_network::layer::IssuedApdu {
                apdu: apdu_bytes,
                next_hop: source_mac,
                destination: source_network,
                expecting_reply: false,
                priority: NetworkPriority::Normal,
            },
            route,
        ) {
            Ok(npdu_buf) => {
                let _ = tx.send(npdu_buf.freeze());
            }
            Err(error) => {
                warn!(%error, "Failed to encode NPDU for MS/TP replay");
                if let Err(error) = BACnetServer::<T>::send_confirmed_response_apdu(
                    network,
                    apdu_bytes,
                    source_mac,
                    source_network,
                    route,
                )
                .await
                {
                    warn!(%error, "Failed to send replay");
                }
            }
        }
    } else if let Err(error) = BACnetServer::<T>::send_confirmed_response_apdu(
        network,
        apdu_bytes,
        source_mac,
        source_network,
        route,
    )
    .await
    {
        warn!(%error, "Failed to send replay");
    }
}

/// Where a confirmed-service response goes: the requester's MAC, its network
/// address when routed, and the route the request arrived on.
#[derive(Clone, Copy)]
pub(in crate::server) struct ResponseTarget<'a> {
    pub(in crate::server) source_mac: &'a [u8],
    pub(in crate::server) source_network: Option<&'a NpduAddress>,
    pub(in crate::server) route: &'a bacnet_network::response_route::ResponseRoute,
}

async fn send_response<T: TransportPort + 'static>(
    network: &NetworkLayer<T>,
    buf: BytesMut,
    target: ResponseTarget<'_>,
    reply_tx: Option<tokio::sync::oneshot::Sender<Bytes>>,
    log_errors: bool,
    pending: Option<PendingConfirmedRequest>,
) -> bool {
    let ResponseTarget {
        source_mac,
        source_network,
        route,
    } = target;
    let reply_tx = if route.requires_direct_response() {
        None
    } else {
        reply_tx
    };
    let apdu_bytes = buf.freeze();
    if let Some(tx) = reply_tx {
        match network.encode_response_for_handoff(
            bacnet_network::layer::IssuedApdu {
                apdu: &apdu_bytes,
                next_hop: source_mac,
                destination: source_network,
                expecting_reply: false,
                priority: NetworkPriority::Normal,
            },
            route,
        ) {
            Ok(npdu_buf) => {
                let handed_off = tx.send(npdu_buf.freeze()).is_ok();
                // Synchronous reply-channel handoff, not the serial worker's
                // later turnaround. A failed handoff releases too, but is not
                // reported as a successful reply.
                drop(pending);
                if !handed_off && log_errors {
                    warn!("MS/TP reply receiver closed before response handoff");
                }
                return handed_off;
            }
            Err(error) => {
                if log_errors {
                    warn!(%error, "Failed to encode NPDU for MS/TP reply");
                }
            }
        }
    }
    let sent = BACnetServer::<T>::issue_terminal_response(
        network,
        &apdu_bytes,
        source_mac,
        source_network,
        route,
        pending,
    )
    .await;
    if let Err(error) = &sent {
        if log_errors {
            warn!(%error, "Failed to send response");
        }
    }
    sent.is_ok()
}

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Convert an error into its protocol response APDU.
    pub(in crate::server) fn error_apdu_from_error(
        invoke_id: u8,
        service_choice: ConfirmedServiceChoice,
        error: &Error,
    ) -> Apdu {
        error_apdu_from_error(invoke_id, service_choice, error)
    }
}

#[cfg(test)]
#[path = "../alarm_summary_tests.rs"]
mod alarm_summary_tests;

#[cfg(test)]
#[path = "typed_error_reply_tests.rs"]
mod typed_error_reply_tests;

#[cfg(test)]
mod encoded_apdu_tests {
    use super::*;

    /// The one encoding a response now gets (#1713) is the encoder's own.
    #[test]
    fn encoded_apdu_is_the_encoder_output_for_every_reply_kind() {
        let replies = [
            Apdu::SimpleAck(SimpleAck {
                invoke_id: 7,
                service_choice: ConfirmedServiceChoice::WRITE_PROPERTY,
            }),
            Apdu::ComplexAck(ComplexAck {
                segmented: false,
                more_follows: false,
                invoke_id: 7,
                sequence_number: None,
                proposed_window_size: None,
                service_choice: ConfirmedServiceChoice::READ_PROPERTY,
                service_ack: Bytes::from(vec![0x5a; 1400]),
            }),
            error_apdu_from_error(
                7,
                ConfirmedServiceChoice::READ_PROPERTY,
                &Error::Protocol {
                    class: ErrorClass::OBJECT,
                    code: ErrorCode::UNKNOWN_OBJECT,
                },
            ),
            Apdu::Reject(RejectPdu {
                invoke_id: 7,
                reject_reason: RejectReason::UNRECOGNIZED_SERVICE,
            }),
            Apdu::Abort(AbortPdu {
                sent_by_server: true,
                invoke_id: 7,
                abort_reason: AbortReason::OUT_OF_RESOURCES,
            }),
        ];
        for reply in &replies {
            let mut expected = BytesMut::new();
            encode_apdu(&mut expected, reply).unwrap();
            assert_eq!(encoded_apdu(reply), expected, "{reply:?}");
        }
    }
}
