# Abandon an interrupted module repository addition

Startup recovery will not reinstall a missing publisher key: it may have been deliberately revoked. If the intended repository is not visible and its key is absent, root can choose to abandon that addition rather than retry it. This is an offline host operation, not a Modules API action.

1. Keep package changes, source edits, and other operators' work paused. In a root-only working directory, make a private copy of `/etc/panasms/module-sources.pending.json`. Review **that copy**: check the `Add` ID, URL, publisher and fingerprint, and confirm that this is the addition to discard. Inspect the current source list and publisher key directory without changing either. Do not delete the pending file or restore the key to force replay.
2. Run `sha256sum` on the reviewed copy. Use its literal 64-character lowercase digest (not the publisher fingerprint or a digest calculated from a later live read):

   ```sh
   sudo /usr/lib/panasms/panasms-system-helper modules abandon-source-add REVIEWED_JOURNAL_SHA256
   ```

3. On success the original journal bytes remain in `/etc/panasms/module-sources.abandoned-<digest>.json`. No source or key is written. A retry with the same digest confirms the archive if no intent is pending. After an interruption or sync error retry the **same** command, not a newly calculated digest. A changed pending intent, a visible matching ID or URL, a present publisher key, or a publication stage requires separate review; do not remove evidence to make the command pass.

Resume normal recovery. Adding the repository later requires a new review and approval; the archived journal is not an authorization to add it.
