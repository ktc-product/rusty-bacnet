---
section: Added
---
- A Network Port can let clients write Network_Number, pending until ReinitializeDevice
  ACTIVATE_CHANGES or WARMSTART (`NetworkPortObject::allow_network_number_writes`). Activation
  is refused when two ports would end up on one number.
  `ObjectDatabase::network_numbers_in_effect` lists the numbers the ports run on.
