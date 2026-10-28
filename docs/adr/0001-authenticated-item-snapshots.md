# Keep restorable item snapshots inside the authenticated vault

Structured payload version 2 stores bounded item snapshots inside the existing
vault envelope, with exact item/group/vault validation and atomic mutation with
current content. This reuses reviewed vault encryption and reachable keys instead
of extending the legacy isolated history format with another wrapping hierarchy.
The trade-off is that snapshots share the vault's authorization and rewrite cost;
they are not independently shareable. Legacy history remains metadata-only, and
permanent removal deletes the live item's retained snapshots.
