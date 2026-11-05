# Committed synth output

`FipMemberStack.template.json` is the member-account payload, checked in so
that:

- the diff of what actually lands in a member account is reviewable, and
- an operator can deploy it in an emergency with no Node toolchain —
  plain `aws cloudformation deploy`, or as a StackSet template.

It is environment-agnostic: the orchestrator account arrives as the
`OrchestratorAccountId` parameter, so this one file serves every
deployment. Regenerate with `npm run synth:member` and copy from
`cdk.out/`.

`FipCoreStack` is deliberately **not** committed here. It resolves
concrete account and region values into bucket names at synth time, so a
checked-in copy would either carry someone's account ID or carry a
placeholder that is wrong everywhere. Synthesize it against the real
evidence account when the account exists.
