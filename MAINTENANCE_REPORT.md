# Maintenance Report — hivemind-websocket-client

## 2026-03-23

- **AI Model**: Claude Opus 4.6
- **Actions Taken**:
  - Added `on_query` decorator to `decorators.py` (was missing; `on_cascade` already existed)
  - Fixed duplicate `route` kwarg bug in `HiveMessage.deserialize()` (`message.py:211`)
  - Added unit tests for `handle_query` and `handle_cascade` protocol handlers (`test_protocol.py`): BUS dispatch, INTERCOM dispatch, invalid inner type assertion
  - Added unit test for `on_query` decorator (`test_decorators.py`)
  - Updated `docs/message_types.md` with QUERY and CASCADE sections
  - Updated `docs/api.md` to include QUERY, CASCADE, RENDEZVOUS in enum table
  - Created `FAQ.md`, `MAINTENANCE_REPORT.md`, `AUDIT.md`
- **Oversight**: Human review pending before push
