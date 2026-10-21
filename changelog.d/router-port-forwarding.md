---
section: Added
---
- A router port can be set not to forward (`PortConfig::forwarding`,
  `RouterOptions::not_forwarding`, `BACnetRouter::set_forwarding`): the
  router's own application still uses it, but nothing is routed to or from it.
