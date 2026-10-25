# Background checks

Gatekeeper requires Authum's background task API. An older host without it is
reported as unsupported; there is no synchronous fallback that could stall HLDS.
Build with the updated `lib/authum`, or set `-DAUTHUM_DIR=/path/to/authum`.

ClientConnect only records the IP and a new slot generation, then allows the
connection. ClientPutInServer queues a check with the current SteamID/userid.
SQL, whitelist-file reads and IPHub run in the module's FIFO worker. Each check
opens its own connection, ensures the schema, resolves the IP, updates the client
and ASN history, and calculates a decision. SQLite and MySQL share this path.

On a later game frame, buffered logs are written, the resolved event is
published and a denied player is kicked. Thus a denied player can briefly enter
the game before being removed. Before using a result (and again before kicking),
gatekeeper checks slot generation and engine userid. Disconnect/reconnect and
map deactivation invalidate previous results. Worker code never kicks players or
publishes events.

Database errors, an unavailable/full queue, and missing IP data allow the player
and are logged distinctly. A later check opens a new connection; gatekeeper does
not need a reload after a database restart. Already admitted players are not
automatically rechecked after a failed check. Pending requests are bounded by
Authum's 64-task owner queue. Slow requests can delay checks for other players
of this module, but not the game loop. Unload waits for the active task before
freeing module code; DNS timing still follows the OS resolver.

Legacy sql_connect_delay_ms/sql_connect_retries/sql_connect_retry_ms no longer
apply: connecting is part of each background check. Authum/lh use bounded MySQL
network timeouts. IPHub uses its configured socket timeout and the OS resolver.

Tests cover actual worker execution, main-thread delivery, queue bounds,
cancellation, current-client guards, disconnect/reconnect and map changes.
The local HLDS lab additionally checks delayed kicks and frame progress during
two-second worker operations for SQLite and MySQL.
