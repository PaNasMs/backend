# Events v1

Authenticated same-origin WebSocket: `/api/v1/events`, session cookie required.
Server messages: `{ "version": 1, "type": "...", "data": ... }`.

- `resync`: reread HTTP snapshots after opening/reopening the connection.
- `storage.changed`: invalidate storage snapshot and read `/api/v1/storage`.
- `metrics`: data matches the OpenAPI Metrics schema.
- `cooling`: current CoolingState, including applied profile and duty (not RPM).
- `cooling.unavailable`: mark the last cooling snapshot unavailable.
- `metrics.unavailable`: invalidate the metric snapshot and display its failure.
- `notifications.changed`: reread persisted alerts and device event history; initial snapshots do not trigger toasts.
- `jobs.changed`: reread the persistent job list and affected module snapshots.

No browser commands are accepted on this stream. Mutations use the authorized
HTTP plan/run API. Jobs persist in the agent's SQLite database; these WebSocket
invalidations are ephemeral. Replay cursors are not implemented.
A full HTTP resync is required after any reconnect. Slow clients are disconnected.
Session access is revalidated periodically; a revoked/expired session closes
with code 1008. Origin checks are enforced by the WebSocket server.
