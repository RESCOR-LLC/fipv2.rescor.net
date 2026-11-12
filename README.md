# FIP — Forensic Isolation Program

FIP contains a potentially compromised EC2 instance, acquires forensic copies of its
volumes, and lands the evidence in a dedicated forensic account under your own key,
with a signed chain-of-custody manifest.

- **Isolate**: every network interface moved to a security group with no rules;
  detached from its Auto Scaling group without a replacement.
- **Acquire and verify**: crash-consistent snapshots, hashed over the block stream
  without attaching or booting anything.
- **Move and attest**: copies re-encrypted under your forensic key in a separate
  account, with a signed manifest in an Object Lock bucket.
- **Release and restore**: hand evidence to an examiner's account, and put an
  instance back on its original security groups, each as a signed custody record.
- **Examine, optionally**: an isolated workstation in an analysis account, which may be
  a third party's. No route off its VPC, reached only by logged Session Manager
  sessions, with buckets for bringing tools in and getting findings out.
- **Keep an incident together**: an incident case gathers every run, ticket, comment,
  release and restore of one incident in a signed, chained log.

FIP never terminates an instance and never deletes a snapshot.

## Start here

**[docs/MANUAL.md](docs/MANUAL.md)**: install, run a case, and the full `fip`
command reference.

| | |
|---|---|
| [docs/MANUAL.md](docs/MANUAL.md) | Installation and operations |
| [cdk/](cdk/README.md) | The stacks and the `fip` CLI |
| [cdk/RECOVERY.md](cdk/RECOVERY.md) | Teardown and rebuild |
| [docs/architecture/](docs/architecture/README.md) | C4 model |

## Requirements

Node.js 20+, `jq`, `openssl`, AWS CLI v2, and one AWS account or more.
AWS Organizations is optional.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
