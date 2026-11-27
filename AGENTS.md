# Caplock repository instructions

## Overall goal

Turn enterprise security policies, MCP tool inventories, and optionally historical
tool-call logs into four verifiable outputs:

1. least-privilege policies with an allow matrix and exportable policy artifacts;
2. attack-path and blast-radius reports;
3. a deterministic policy regression suite;
4. runtime interception or SDK rules connected to an MCP proxy.

The first release deliberately starts with MCP tool-call permissions. Inventory,
locking, structured policy compilation, and lint are upstream layers; they are
not runtime enforcement or proof of least privilege by themselves.

## Goal checkpoint after every implementation

At the end of every implementation or documentation milestone, include a short
goal regression covering:

- which part of the overall goal this milestone advances;
- capabilities that are complete, with concrete evidence;
- capabilities that are only partial, with the exact missing behavior;
- remaining goals in dependency order;
- verification performed and known limitations.

Do not describe structured YAML/JSON policy compilation as natural-language policy
compilation, or lint as enforcement. Keep those gaps explicit until the related
evaluator, regression, report, and runtime layers exist.

## Deployment confirmation

Never deploy, upload, publish, or restart a service unless the user explicitly
asks for deployment or confirms it in the current conversation. Do not deploy as
an automatic follow-up to implementation.
