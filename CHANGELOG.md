# Changelog

## [1.1.0a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.1.0a1) (2026-09-04)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.20a1...1.1.0a1)

**Merged pull requests:**

- feat: transparent multi-frame chunking for the v3 Noise transport [\#216](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/216) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.20a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.20a1) (2026-09-02)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.19a1...1.0.20a1)

**Merged pull requests:**

- fix: harden async and http client transports [\#213](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/213) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.19a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.19a1) (2026-09-02)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.18a1...1.0.19a1)

**Merged pull requests:**

- fix: preserve empty-bytes payload instead of coercing to empty dict [\#212](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/212) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.18a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.18a1) (2026-09-02)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.17a1...1.0.18a1)

**Merged pull requests:**

- fix: warn when close\(\) worker join times out [\#210](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/210) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.17a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.17a1) (2026-09-02)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.16a1...1.0.17a1)

**Merged pull requests:**

- fix: close\(\) joins its reconnect worker thread so callers get a clean stop [\#207](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/207) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.16a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.16a1) (2026-09-01)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.15a2...1.0.16a1)

**Merged pull requests:**

- fix: respect caller-supplied session\_id/site\_id in emit\(\) [\#205](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/205) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.15a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.15a2) (2026-08-15)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.15a1...1.0.15a2)

**Merged pull requests:**

- docs: add AGENTS.md with per-repo agent conventions [\#203](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/203) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.15a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.15a1) (2026-08-14)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.14a1...1.0.15a1)

**Merged pull requests:**

- fix: add handshake\_max\_retries to async client connect\(\) [\#201](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/201) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.14a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.14a1) (2026-08-14)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.13a1...1.0.14a1)

**Merged pull requests:**

- fix: run\_forever\(\) blocks on an existing worker instead of raising [\#199](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/199) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.13a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.13a1) (2026-08-13)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.12a1...1.0.13a1)

**Merged pull requests:**

- fix: emit\(\) must not block the caller's loop when the transport is down [\#197](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/197) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.12a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.12a1) (2026-08-13)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.11a1...1.0.12a1)

**Merged pull requests:**

- fix: make peer-to-peer INTERCOM actually arrive [\#189](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/189) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.11a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.11a1) (2026-08-13)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.10a1...1.0.11a1)

## [1.0.10a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.10a1) (2026-08-13)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.9a1...1.0.10a1)

**Merged pull requests:**

- fix: make the hive map readable, and show the nodes that answered [\#191](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/191) ([JarbasAl](https://github.com/JarbasAl))
- fix: a node has one identity, and connecting somewhere must not rewrite it [\#190](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/190) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.9a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.9a1) (2026-08-13)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.8a1...1.0.9a1)

**Merged pull requests:**

- fix: tolerate malformed route entries in update\_hop\_data [\#192](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/192) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.8a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.8a1) (2026-08-12)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.7a1...1.0.8a1)

**Closed issues:**

- protocol v3: a client with a stale Noise pin locks itself out permanently \(KKpsk0 retry loop, no XXpsk2 fallback\) [\#186](https://github.com/JarbasHiveMind/hivemind-websocket-client/issues/186)

**Merged pull requests:**

- fix: recover from a stale Noise pin instead of looping on KKpsk0 forever [\#187](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/187) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.7a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.7a1) (2026-08-10)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.6a3...1.0.7a1)

**Merged pull requests:**

- fix: stop reconnecting when the hub refuses the identity [\#184](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/184) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.6a3](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.6a3) (2026-08-10)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.6a2...1.0.6a3)

**Merged pull requests:**

- docs: correct claims that no longer match the code [\#182](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/182) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.6a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.6a2) (2026-08-10)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.6a1...1.0.6a2)

**Merged pull requests:**

- chore\(ci\): drop the broken, redundant Dependabot config [\#180](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/180) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.6a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.6a1) (2026-08-10)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.5a1...1.0.6a1)

**Merged pull requests:**

- fix: bound the QUERY originator's wait and the binary metadata block [\#177](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/177) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.5a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.5a1) (2026-08-10)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.4a1...1.0.5a1)

**Merged pull requests:**

- docs: remove stale WIRE-1 §4.2 divergence comment in serialization.py [\#175](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/175) ([JarbasAl](https://github.com/JarbasAl))
- fix: make the flood id cache thread safe [\#173](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/173) ([JarbasAl](https://github.com/JarbasAl))
- fix: reconnect wait can reach 90s despite the 60s cap [\#172](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/172) ([JarbasAl](https://github.com/JarbasAl))
- fix: a rejected handshake must not brick the satellite [\#171](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/171) ([JarbasAl](https://github.com/JarbasAl))
- fix: emit honours the message's own bin\_type [\#159](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/159) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.4a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.4a1) (2026-08-04)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.3a1...1.0.4a1)

**Merged pull requests:**

- fix: bound HiveMapper memory growth [\#170](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/170) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.3a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.3a1) (2026-08-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.2a1...1.0.3a1)

**Merged pull requests:**

- fix: jitter the reconnect backoff so a restart does not resynchronize the fleet [\#168](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/168) ([JarbasAl](https://github.com/JarbasAl))
- feat: accept a precomputed psk in start\_noise\_handshake [\#167](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/167) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.2a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.2a1) (2026-08-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.1a1...1.0.2a1)

**Merged pull requests:**

- fix: keep every route hop that names a source [\#158](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/158) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.1a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.1a1) (2026-08-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/1.0.0a1...1.0.1a1)

**Merged pull requests:**

- fix: keep the envelope route across a binary frame [\#164](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/164) ([JarbasAl](https://github.com/JarbasAl))

## [1.0.0a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/1.0.0a1) (2026-08-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.11.1a1...1.0.0a1)

**Breaking changes:**

- feat!: remove the THIRDPRTY message type [\#160](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/160) ([JarbasAl](https://github.com/JarbasAl))

## [0.11.1a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.11.1a1) (2026-08-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.11.0a1...0.11.1a1)

**Merged pull requests:**

- fix: share one PING flood cache per node [\#161](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/161) ([JarbasAl](https://github.com/JarbasAl))

## [0.11.0a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.11.0a1) (2026-08-02)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.10.6a2...0.11.0a1)

**Merged pull requests:**

- feat: HiveMessage.forward\(\) derives envelopes without losing fields [\#154](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/154) ([JarbasAl](https://github.com/JarbasAl))

## [0.10.6a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.10.6a2) (2026-08-02)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.10.6a1...0.10.6a2)

**Merged pull requests:**

- docs: correct stale API, CLI, and identity claims [\#153](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/153) ([JarbasAl](https://github.com/JarbasAl))

## [0.10.6a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.10.6a1) (2026-08-02)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.10.5a2...0.10.6a1)

**Merged pull requests:**

- fix: never mislabel an unencodable message type as THIRDPRTY [\#151](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/151) ([JarbasAl](https://github.com/JarbasAl))

## [0.10.5a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.10.5a2) (2026-08-02)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.10.5a1...0.10.5a2)

**Merged pull requests:**

- test: cover the XX-path pinned-key mismatch abort \(CRYPTO-1 §3.4.5\) [\#149](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/149) ([JarbasAl](https://github.com/JarbasAl))

## [0.10.5a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.10.5a1) (2026-08-02)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.10.4a1...0.10.5a1)

**Merged pull requests:**

- fix: keep synchronous client reconnecting after websocket closes [\#141](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/141) ([goldyfruit](https://github.com/goldyfruit))

## [0.10.4a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.10.4a1) (2026-08-02)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.10.3a1...0.10.4a1)

**Merged pull requests:**

- refactor: construct legacy password handshake only when selected [\#142](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/142) ([goldyfruit](https://github.com/goldyfruit))

## [0.10.3a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.10.3a1) (2026-08-02)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.10.2a3...0.10.3a1)

**Merged pull requests:**

- fix: reject unassigned/reserved binary type codes per WIRE-1 §4.2 [\#145](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/145) ([JarbasAl](https://github.com/JarbasAl))

## [0.10.2a3](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.10.2a3) (2026-07-31)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.10.2a2...0.10.2a3)

**Merged pull requests:**

- docs: rewrite README in Simplified Technical English [\#143](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/143) ([JarbasAl](https://github.com/JarbasAl))

## [0.10.2a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.10.2a2) (2026-07-06)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.10.2a1...0.10.2a2)

**Closed issues:**

- Allow poorman-handshake 2 in the websocket client [\#138](https://github.com/JarbasHiveMind/hivemind-websocket-client/issues/138)

**Merged pull requests:**

- Allow poorman-handshake 2 [\#139](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/139) ([goldyfruit](https://github.com/goldyfruit))

## [0.10.2a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.10.2a1) (2026-07-04)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.10.1a1...0.10.2a1)

**Merged pull requests:**

- fix: async client negotiates v3 Noise + awaits handshake emit [\#136](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/136) ([JarbasAl](https://github.com/JarbasAl))

## [0.10.1a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.10.1a1) (2026-07-04)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.10.0a1...0.10.1a1)

**Merged pull requests:**

- fix: keep hivemind-core git ref out of package metadata \(unblock PyPI publish\) [\#134](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/134) ([JarbasAl](https://github.com/JarbasAl))

## [0.10.0a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.10.0a1) (2026-07-04)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.9.2a1...0.10.0a1)

**Merged pull requests:**

- feat: protocol v3 Noise handshake client \(XXpsk2/KKpsk0\) with v2 fallback [\#131](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/131) ([JarbasAl](https://github.com/JarbasAl))

## [0.9.2a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.9.2a1) (2026-06-06)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.9.1a1...0.9.2a1)

**Merged pull requests:**

- fix\(deps\): require ovos-bus-client\>=2.0.0a3 \(drops bundled hivemind protocol\) [\#128](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/128) ([JarbasAl](https://github.com/JarbasAl))

## [0.9.1a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.9.1a1) (2026-06-05)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.9.0a4...0.9.1a1)

**Merged pull requests:**

- fix: QUERY/CASCADE response companion [\#124](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/124) ([JarbasAl](https://github.com/JarbasAl))

## [0.9.0a4](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.9.0a4) (2026-06-05)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.9.0a3...0.9.0a4)

**Merged pull requests:**

- docs: zero-to-hero README + library guide [\#125](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/125) ([JarbasAl](https://github.com/JarbasAl))

## [0.9.0a3](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.9.0a3) (2026-06-05)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.9.0a2...0.9.0a3)

**Merged pull requests:**

- ci: fix broken coverage job \(async tests need pytest-asyncio\) [\#122](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/122) ([JarbasAl](https://github.com/JarbasAl))

## [0.9.0a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.9.0a2) (2026-06-05)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.9.0a1...0.9.0a2)

**Merged pull requests:**

- build: bump stale OVOS dep floors to the modern major [\#120](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/120) ([JarbasAl](https://github.com/JarbasAl))

## [0.9.0a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.9.0a1) (2026-05-18)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.8.0a1...0.9.0a1)

**Merged pull requests:**

- feat: AsyncFakeHiveMessageBus alongside the async client [\#117](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/117) ([JarbasAl](https://github.com/JarbasAl))

## [0.8.0a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.8.0a1) (2026-05-18)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.7.0a2...0.8.0a1)

**Fixed bugs:**

- assert message.msg\_type == HiveMessageType.PING [\#108](https://github.com/JarbasHiveMind/hivemind-websocket-client/issues/108)
- AttributeError: 'dict' object has no attribute 'msg\_type' [\#104](https://github.com/JarbasHiveMind/hivemind-websocket-client/issues/104)

**Merged pull requests:**

- feat: AsyncHiveMessageBusClient \(asyncio-native client\) [\#115](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/115) ([JarbasAl](https://github.com/JarbasAl))

## [0.7.0a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.7.0a2) (2026-05-07)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.7.0a1...0.7.0a2)

## [0.7.0a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.7.0a1) (2026-05-07)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.6.1a1...0.7.0a1)

**Merged pull requests:**

- feat\(tests\): hivescope e2e suite + CI [\#112](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/112) ([JarbasAl](https://github.com/JarbasAl))

## [0.6.1a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.6.1a1) (2026-05-07)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.6.0a1...0.6.1a1)

**Merged pull requests:**

- fix: message typing [\#107](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/107) ([JarbasAl](https://github.com/JarbasAl))

## [0.6.0a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.6.0a1) (2026-03-23)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.5.0a6...0.6.0a1)

**Merged pull requests:**

- feat: implement QUERY and CASCADE message handlers \(satellite side\) [\#101](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/101) ([JarbasAl](https://github.com/JarbasAl))

## [0.5.0a6](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.5.0a6) (2026-03-23)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.5.0a5...0.5.0a6)

**Merged pull requests:**

- chore: remove dead code [\#99](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/99) ([JarbasAl](https://github.com/JarbasAl))

## [0.5.0a5](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.5.0a5) (2026-03-23)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.5.0a4...0.5.0a5)

**Merged pull requests:**

- chore: Docs and tests [\#97](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/97) ([JarbasAl](https://github.com/JarbasAl))

## [0.5.0a4](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.5.0a4) (2026-03-23)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.5.0a3...0.5.0a4)

## [0.5.0a3](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.5.0a3) (2026-03-23)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.5.0a2...0.5.0a3)

## [0.5.0a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.5.0a2) (2026-03-23)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.5.0a1...0.5.0a2)

## [0.5.0a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.5.0a1) (2026-03-23)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.6a3...0.5.0a1)

**Merged pull requests:**

- feat: add flood-based PING network discovery and hive topology mapping [\#90](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/90) ([JarbasAl](https://github.com/JarbasAl))

## [0.4.6a3](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.6a3) (2026-03-23)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.6a2...0.4.6a3)

**Merged pull requests:**

- chore: typing, Docs, tests [\#91](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/91) ([JarbasAl](https://github.com/JarbasAl))

## [0.4.6a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.6a2) (2026-03-21)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.6a1...0.4.6a2)

**Merged pull requests:**

- Fix: z85 [\#87](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/87) ([JarbasAl](https://github.com/JarbasAl))

## [0.4.6a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.6a1) (2026-01-23)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.5a3...0.4.6a1)

**Merged pull requests:**

- fix: add warning if websocket connection isnt open [\#83](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/83) ([JarbasAl](https://github.com/JarbasAl))

## [0.4.5a3](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.5a3) (2026-01-23)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.5a2...0.4.5a3)

**Merged pull requests:**

- chore\(deps\): update actions/checkout action to v6 [\#79](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/79) ([renovate[bot]](https://github.com/apps/renovate))

## [0.4.5a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.5a2) (2025-12-19)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.5a1...0.4.5a2)

**Merged pull requests:**

- chore\(deps\): update actions/setup-python action to v6 [\#81](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/81) ([renovate[bot]](https://github.com/apps/renovate))

## [0.4.5a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.5a1) (2025-12-18)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.4...0.4.5a1)

**Merged pull requests:**

- chore: Configure Renovate [\#76](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/76) ([renovate[bot]](https://github.com/apps/renovate))

## [0.4.4](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.4) (2025-12-18)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.4a1...0.4.4)

**Merged pull requests:**

- Release 0.4.4a1 [\#75](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/75) ([github-actions[bot]](https://github.com/apps/github-actions))

## [0.4.4a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.4a1) (2025-12-18)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.3...0.4.4a1)

**Closed issues:**

- FEAT: Mac support [\#68](https://github.com/JarbasHiveMind/hivemind-websocket-client/issues/68)

**Merged pull requests:**

- fix: payload context update [\#73](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/73) ([JarbasAl](https://github.com/JarbasAl))
- fix: defensive check for potential missing key [\#69](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/69) ([mikejgray](https://github.com/mikejgray))

## [0.4.3](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.3) (2025-02-07)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.2...0.4.3)

## [0.4.2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.2) (2025-01-08)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.2a1...0.4.2)

**Merged pull requests:**

- Release 0.4.2a1 [\#67](https://github.com/JarbasHiveMind/hivemind-websocket-client/pull/67) ([github-actions[bot]](https://github.com/apps/github-actions))

## [0.4.2a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.2a1) (2025-01-08)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.1a2...0.4.2a1)

## [0.4.1a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.1a2) (2025-01-08)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.1a1...0.4.1a2)

## [0.4.1a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.1a1) (2025-01-08)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.0...0.4.1a1)

## [0.4.0](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.0) (2025-01-08)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.4.0a1...0.4.0)

## [0.4.0a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.4.0a1) (2025-01-08)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.3.0a2...0.4.0a1)

## [0.3.0a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.3.0a2) (2025-01-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.3.0a1...0.3.0a2)

## [0.3.0a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.3.0a1) (2025-01-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.2.1...0.3.0a1)

## [0.2.1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.2.1) (2025-01-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.2.1a1...0.2.1)

## [0.2.1a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.2.1a1) (2025-01-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.2.0...0.2.1a1)

## [0.2.0](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.2.0) (2025-01-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.2.0a1...0.2.0)

## [0.2.0a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.2.0a1) (2025-01-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.6...0.2.0a1)

## [0.1.6](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.6) (2025-01-02)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.6a1...0.1.6)

## [0.1.6a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.6a1) (2025-01-01)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.5...0.1.6a1)

## [0.1.5](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.5) (2025-01-01)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.5a2...0.1.5)

## [0.1.5a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.5a2) (2025-01-01)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.5a1...0.1.5a2)

## [0.1.5a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.5a1) (2025-01-01)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.4...0.1.5a1)

## [0.1.4](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.4) (2024-12-30)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.4a1...0.1.4)

## [0.1.4a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.4a1) (2024-12-30)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.3...0.1.4a1)

## [0.1.3](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.3) (2024-12-23)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.3a2...0.1.3)

## [0.1.3a2](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.3a2) (2024-12-23)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.3a1...0.1.3a2)

## [0.1.3a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.3a1) (2024-12-21)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.2a1...0.1.3a1)

## [0.1.2a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.2a1) (2024-12-21)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.1...0.1.2a1)

## [0.1.1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.1) (2024-11-29)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.0...0.1.1)

## [0.1.0](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.0) (2024-10-30)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.1.0a1...0.1.0)

## [0.1.0a1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.1.0a1) (2024-10-30)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.0.4...0.1.0a1)

## [0.0.4](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.0.4) (2024-10-25)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.0.4a0...0.0.4)

## [0.0.4a0](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.0.4a0) (2024-10-25)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a29...0.0.4a0)

## [V0.0.4a29](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a29) (2024-10-24)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a28...V0.0.4a29)

## [V0.0.4a28](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a28) (2024-10-24)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a27...V0.0.4a28)

## [V0.0.4a27](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a27) (2024-07-12)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a26...V0.0.4a27)

## [V0.0.4a26](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a26) (2024-06-12)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a25...V0.0.4a26)

## [V0.0.4a25](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a25) (2024-06-05)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a24...V0.0.4a25)

## [V0.0.4a24](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a24) (2024-06-04)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a23...V0.0.4a24)

## [V0.0.4a23](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a23) (2024-05-30)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a22...V0.0.4a23)

## [V0.0.4a22](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a22) (2024-05-21)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a20...V0.0.4a22)

## [V0.0.4a20](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a20) (2024-05-20)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a21...V0.0.4a20)

## [V0.0.4a21](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a21) (2024-05-20)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a19...V0.0.4a21)

## [V0.0.4a19](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a19) (2024-04-21)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a18...V0.0.4a19)

## [V0.0.4a18](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a18) (2024-01-16)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a17...V0.0.4a18)

## [V0.0.4a17](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a17) (2023-11-21)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a16...V0.0.4a17)

## [V0.0.4a16](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a16) (2023-10-31)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a15...V0.0.4a16)

## [V0.0.4a15](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a15) (2023-10-31)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a14...V0.0.4a15)

## [V0.0.4a14](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a14) (2023-10-26)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a13...V0.0.4a14)

## [V0.0.4a13](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a13) (2023-10-26)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a12...V0.0.4a13)

## [V0.0.4a12](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a12) (2023-10-17)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a11...V0.0.4a12)

## [V0.0.4a11](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a11) (2023-09-29)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a10...V0.0.4a11)

## [V0.0.4a10](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a10) (2023-09-14)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a9...V0.0.4a10)

## [V0.0.4a9](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a9) (2023-09-14)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a8...V0.0.4a9)

## [V0.0.4a8](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a8) (2023-09-12)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a7...V0.0.4a8)

## [V0.0.4a7](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a7) (2023-09-06)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a6...V0.0.4a7)

## [V0.0.4a6](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a6) (2023-08-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a5...V0.0.4a6)

## [V0.0.4a5](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a5) (2023-08-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/V0.0.4a4...V0.0.4a5)

## [V0.0.4a4](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/V0.0.4a4) (2023-08-03)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/0.0.1...V0.0.4a4)

## [0.0.1](https://github.com/JarbasHiveMind/hivemind-websocket-client/tree/0.0.1) (2021-04-22)

[Full Changelog](https://github.com/JarbasHiveMind/hivemind-websocket-client/compare/50c474cc7afa10809e712839621b0f28a364d0f8...0.0.1)



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
