# Team decision record

Team name: teach

## Findings

One row per flaw. **Type** must be one of: `sensor`, `constraint`, `actuation`.

| # | Where (file) | What is wrong | Type |
|---|---|---|---|
| 1 | infra/iam/deploy-role-policy.json | IAM deploy-role uses a NotAction wildcard, granting over-privileged admin permissions | constraint |
| 2 | infra/terraform/storage.tf, database.tf | Public S3 reports bucket and a publicly_accessible RDS database leave sensitive data exposed | constraint |
| 3 | pipeline/ci-cd.yml | Hard-coded database password / registry_password secret sits in plaintext pipeline vars | constraint |
| 4 | app/requirements.txt, app/Dockerfile | Dependency supply-chain risk: unpinned requirements and an unverified Dockerfile ADD of fonts with no checksum | constraint |
| 5 | pipeline/ci-cd.yml | The security scan gate is soft-fail / non-blocking, so it never stops a bad build before production | constraint |
| 6 | infra/terraform/network.tf | The build-agent security group allows egress to 0.0.0.0/0 (wide-open bootstrap outbound) | constraint |
| 7 | infra/terraform/monitoring.tf | No CloudTrail / GuardDuty telemetry; logging disabled means no monitoring or detection visibility | sensor |
| 8 | pipeline/ci-cd.yml, k8s/deployment.yaml | No rollback / rollout undo on a failed deploy — there is no recovery response path | actuation |

## Verdict

Evaluate the system **as you received it**, before your fixes.

Decision: DO NOT DEPLOY

Rules triggered: Rule 2, Rule 3

Reasoning: The deploy role grants full administrative access via a NotAction wildcard, which breaks Rule 2. Sensitive report data is reachable from the public internet through a public S3 bucket and a publicly accessible RDS instance, which breaks Rule 3. Either one alone blocks deployment; both are present, so the system must not ship as received.
