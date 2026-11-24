# Contributing

Thank you for your interest in SpaceGoat.

## Current state

The project is in early development and its structure is still moving.
Issues and discussion are welcome.

**External code contributions are not accepted yet.**
Contributions will require a contributor licence agreement, and its text has not been published.
This page will be updated when it is.

## Principles a change must respect

- A device connects outbound only and accepts no inbound connection.
- Detection only. No change that adds deauthentication, containment, jamming, password cracking or capture of third-party traffic content will be accepted.
- The hub listens first. Active probing of a network is added only with an explicit, reviewed design, because industrial equipment can fail under a scan.
- Personal data (hardware addresses, device names, IP addresses) is kept apart from other attributes so that it can be redacted.
- Hardware differences belong in a profile (`hub/profiles/`), not in the agent.
