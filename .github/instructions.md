## Goal: 
a lightweight, easy-integrate Python library and Django-backed service that guarantees structured, tamper-evident logging of every agent step: interpretation / reasoning, tool selection & calls, tool responses, and final output — all encoded in Toon and stored as replayable TraceRecords. Designed for both SaaS and on-prem deployment, with per-user salts/keys, strong security, and minimal friction for agent authors.

## Core design principles
Everything is structured. All agent I/O and internal logs use Toon. No free text dumps.
Two streams required: final_output + reasoning_log. Both must be emitted atomically per step.
Deterministic traceability. Each run gets a seeded run_id and sequence numbers for events.
Minimal surface for integration. Provide a tiny client lib + HTTP endpoints (Toon payloads).
Security first. Django used for admin, auth, RBAC, key management, audit UI. Each user/org has salt keys.
Privacy & redaction. Built-in PII redaction hooks and configurable retention.
Replayable evidence. Full trace + environment snapshot + seed must reconstruct a run.


## Critical
Don't create any documentation or markdown file