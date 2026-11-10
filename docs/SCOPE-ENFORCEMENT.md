# Scope Enforcement and Authorization Boundary

## Purpose

HELIOS-NET is intended for assets that the operator owns or is explicitly
authorized to assess. The scope configuration is an allowlist, not a target
discovery mechanism. A target is denied when the scope cannot be loaded or
validated.

## Scope file

The supported configuration shape is a single top-level `scope` mapping with
these keys:

- `domains`: exact domains and their subdomains.
- `cidrs`: IPv4/IPv6 network ranges.
- `ports`: permitted TCP ports.
- `rate_limit`: numeric pacing/concurrency settings consumed by the relevant
  execution paths.

Unknown keys, malformed values, wildcard entries, invalid ports, duplicate
keys in the supported YAML subset, and unreadable files are rejected. JSON
scope files use the same validation rules.

The shipped configuration is an example, not a grant of permission to scan
those assets. Operators must replace it with the written scope for their own
engagement.

## Enforcement sequence

1. The CLI loads the configured scope. A load or validation error refuses the
   command.
2. The orchestrator checks the campaign target before planning execution.
3. The orchestrator checks every planned step target and validates explicit
   `ports`, `web_ports`, and `port` parameters before any step runs.
4. Discovery runners receive the campaign scope and its port allowlist.
5. Asset discovery checks a candidate name before resolution, checks every
   resolved address before connecting, and keeps redirects inside the same
   authorized boundary.
6. Out-of-scope requests are rejected; they must not be converted into a
   permissive fallback.

The CLI's direct `probe` and `assets` paths also validate their requested
targets and explicit ports before invoking the runner.

## Port semantics

A non-empty `ports` list is an explicit TCP port allowlist. Any requested port
outside it is rejected.

For backward compatibility, an empty port list currently means that any TCP
port may be requested for an otherwise authorized target. This is less
restrictive than a least-privilege engagement policy. Production scope files
should therefore enumerate the approved ports explicitly. An empty domain and
CIDR allowlist still denies every target.

## Important boundary

The scope enforcer is an application-level policy boundary. It is not an OS
sandbox, network firewall, or guarantee that arbitrary third-party plugins are
safe. Code that opens sockets outside the orchestrator/approved discovery
runners must accept and enforce the campaign scope explicitly. Do not treat
registration as proof of authorization.

## Required regression coverage

Changes to scope handling must cover:

- allowed and denied IPv4/IPv6 targets;
- exact domain and subdomain matching, including lookalike-domain rejection;
- malformed, missing, wildcard, and unreadable scope files;
- allowed and denied ports;
- planned `ports`, `web_ports`, and singular `port` values;
- DNS answers outside the authorized CIDR;
- redirects that leave the authorized scope;
- proof that a denied target produces no network connection.

Run the scope, asset-discovery, planner, orchestrator, and end-to-end suites
after changing this boundary.
