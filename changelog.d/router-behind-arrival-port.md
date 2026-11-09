---
section: Fixed
---
- A router no longer relays a link broadcast for a network it reaches through another router on
  the link it arrived on; it leaves it to that router (135.1 test 10.2.4.8). Counted as
  `behind_arrival_port`, reported as `Discard::BehindArrivalPort`.
