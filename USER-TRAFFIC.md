# Per-user traffic counters

`GET /user-traffic` on the existing external controller returns cumulative payload bytes for authenticated inbound usernames:

```json
{"epoch":"process-unique-id","users":{"alice":{"upload":123,"download":456}}}
```

The endpoint uses the controller's existing authentication and access controls. Counters include active and closed TCP and UDP connections with `metadata.inboundUser`, and follow the existing global tracker accounting direction and boundaries. Connections without a user and internal trackers excluded from global totals are omitted.

Counters are held in memory, reset when the process restarts, and are independent of the existing global reset. `epoch` changes on restart so a collector can save periodic deltas without mistaking a restart for a counter decrease. This patch does not persist usage; a collector must store snapshots. An unexpected restart loses traffic since the last saved snapshot.
