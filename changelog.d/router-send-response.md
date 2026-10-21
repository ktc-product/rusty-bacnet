---
section: Added
---
- `BACnetRouter::send_response_apdu_on_issuance` answers a request the router delivered to its
  own application, back the way the request came, without a `NetworkLayer`.
