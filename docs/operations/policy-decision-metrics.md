# Policy Decision Metrics

Yalla emits in-process policy authorization metrics through
`telemetry.PolicyDecisionMetrics`. The policy engine records decisions to
`telemetry.DefaultPolicyDecisionMetrics` by default, and `GET /metrics` returns
the snapshot in the standard `yalla.output.v1` envelope under
`data.policy_decisions`.

The metric series are intentionally low cardinality:

- `action`: the bounded control-plane action, for example `project.create`
- `resource_kind`: the policy resource kind, for example `project`
- `decision`: `allowed`, `denied`, `unknown`, or `other`
- `reason`: the stable policy reason, for example `denied_no_capability`

Each series also carries the latest `request_id`, `correlation_id`,
`organization_id`, `project_id`, `environment_id`, `service_id`, `resource_id`,
`principal_id`, and `job_id` observed for that series. Treat those identifiers
as log-join and source-row hints, not dashboard group-by labels. Dashboards
should group only by the low-cardinality fields above.

Incident workflow:

1. Alert on sustained increases in `decision=denied` for high-impact actions
   such as deployment, service mutation, API key management, or backoffice
   publish actions.
2. Break denial spikes down by `reason` to distinguish expired/revoked
   principals, cross-tenant attempts, missing capabilities, scoped grants that
   no longer cover a route, and missing resource scope wiring.
3. Copy the latest `request_id` or `correlation_id` from the series and search
   structured API logs for the same identifier before investigating tenant or
   resource hints.
4. Use `organization_id`, `resource_id`, and the hierarchy ids only to navigate
   tenant-scoped source rows during an incident. They are operational hints,
   not metric labels.
5. For worker or store paths, prefer `AuthorizeCtx` so request/job correlation
   travels into metrics; non-context `Authorize` emits the decision without
   correlation hints.

Policy decision metrics do not record request bodies, API keys, cookies,
database URLs, Dokploy tokens, rendered environment variables, plaintext secret
values, user agents, IP addresses, metadata values, or error strings.
Free-form or unsafe dimension values collapse to `other`, and unsafe
identifiers are omitted.
