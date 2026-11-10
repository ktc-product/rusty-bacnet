---
section: Added
---
- `NetworkPortObject::keep_in_service` for a port whose link the application runs itself without registering it: the port refuses a client's Out_Of_Service write and lists the row read-only, as a bound port does, since TRUE must stop communication through a port the object doesn't own (Clause 12.56).
- A port kept in service takes the Reliability its application works out, such as a link that won't open, through `ReliabilityEval::set_reliability`, with FAULT set in Status_Flags. Any other port refuses it and keeps NO_FAULT_DETECTED, since a port that can report a fault and go out of service would have to take a client's Reliability while out of service.
