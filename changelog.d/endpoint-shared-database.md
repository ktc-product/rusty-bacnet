---
section: Added
---
- An endpoint session can serve a database its caller keeps a handle on,
  such as one a previous session served: `EndpointSession::with_shared_database`
  and `shared_database` on the B/IP and router builders. Starting waits for
  the database's other holders instead of failing while one holds it.
