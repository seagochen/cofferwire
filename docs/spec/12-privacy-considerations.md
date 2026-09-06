# Privacy Considerations (Draft)

`02-threat-model.md` states, at the level of a principle, that the initial
profile does not hide IP addresses, queue access, timing, message length,
TTL or traffic volume from the relay (`CW-THREAT-013`, `CW-THREAT-014`). This
document makes that catalog concrete per profile, so that a specific privacy
claim can be checked against a specific row instead of against the general
principle alone, and states the reference implementation's current, honest
position on operational metrics and correlation.

## What a relay operator can observe

| Profile | Content the relay cannot read | Metadata the relay can still observe |
| --- | --- | --- |
| queue-v1 | message plaintext, authorship of the plaintext | queue identifier, sender/recipient principal, connection source, access time, message length (before padding), TTL, command type and frequency |
| `cofferwire-blob/1` | chunk plaintext, manifest field values | capability identifier, chunk count and sizes, upload/download timing and frequency, lease renewals |
| `receipts/1` | which application object a receipt confirms (it rides inside an ordinary opaque queue-v1 payload) | the same queue-v1 row above, since a receipt is transported as an ordinary message |
| `cofferwire-offline/1` | bundle plaintext, identity seeds, relay hints | nothing beyond ordinary local file access; a bundle is never sent to a relay (`CW-OFFLINE-001`) |

- **CW-PRIVACY-001:** Documentation and user-facing claims about a specific
  profile's privacy properties MUST NOT describe the relay as unable to
  observe a metadata field listed in this document's table for that profile,
  unless a later revision of this document removes that row with a stated
  reason.
- **CW-PRIVACY-002:** A claim that Cofferwire reduces correlation of relay-
  observable metadata (for example, linking two queue accesses by timing or
  size fingerprint) MUST cite an executed experiment demonstrating the
  reduction. No such experiment has been run as of this revision; no such
  claim is made.

## Operational metrics

The reference daemon (`apps/cofferwired`) does not currently collect or
emit any operational metrics or telemetry beyond the process's own HTTP
access behavior, which this specification does not define. If metrics
collection is added to the reference daemon or to any profile built on
Cofferwire, it follows the allow-list discipline already established by
`profiles/family-tree-v1.md`'s `FT-METRIC-001`/`FT-METRIC-002`:

- **CW-PRIVACY-003:** An implementation MUST NOT record, in any operational
  metric, a queue identifier, capability identifier, principal, message or
  blob identifier, key material, or application content, and MUST NOT record
  a value that lets two metric events be correlated to the same queue,
  capability or principal across sessions where that correlation is
  avoidable.
- **CW-PRIVACY-004:** An implementation MAY record aggregate, bucketed
  counters with no attached identifier -- for example a count of requests by
  command type, a bucketed request-latency histogram, or a count of rate-
  limit rejections in a period -- provided `CW-PRIVACY-003` still holds for
  every such counter.

## Relationship to the threat model

This document narrows, and does not replace, `CW-THREAT-013` and
`CW-THREAT-014`: it remains true that opaque queue and capability identifiers
alone do not provide sender anonymity, relationship anonymity or traffic-
analysis resistance, and nothing in this document should be read as
withdrawing that limitation.
