# From Guardrail Metrics to an Agentic Deployment Decision

**Senior ML Engineer - AI Safety Take-Home**

- Calendar window: 3 days
- Expected focused effort: 90 minutes
- Working mode: Individual; AI coding assistants are permitted
- Runtime: Python 3.11+; no external services required

> This is a 90-minute exercise, not a three-day project. The three-day window is scheduling flexibility. Stop after roughly 90 minutes and submit the best complete work you have. Extra volume or polish is not rewarded.

## Scenario

Northwind Financial is preparing an agentic customer-service assistant for its consumer credit-report product. The agent can retrieve approved policy content, read authorized customer records, draft customer communications, open support or dispute cases, and propose selected account updates that require confirmation or human approval.

A text guardrail screens user inputs and assistant outputs. You have inherited a mock black-box guardrail and two labeled evaluation datasets. Leadership now wants a practical answer to two connected questions:

1. How well does this guardrail work, and where does it fail?
2. What does this evidence justify about the agent's deployment mode or "trust" posture?

The guardrail is only one control. It does not inspect retrieved documents, conversation history, tool calls, or tool outputs. The current gateway logs pass/block events but has no active alerting. The planned product supports English and Brazilian Portuguese; the supplied labeled evaluation data is English-only.

## Materials

- `mock_guardrail/guardrail.py` - supplied guardrail; do not modify
- `data/golden_dataset.csv` - 68 labeled input-policy examples
- `data/response_dataset.csv` - 20 labeled output-policy examples
- `deployment_context.json` - system capabilities, control boundaries, and autonomy levels
- `starter/smoke_test.py` - confirms the environment works
- `starter/solution_template.py` - optional skeleton; replace it if you prefer

You may inspect the guardrail source. Treat it as equivalent to reviewing vendor documentation or a model card. Your task is to evaluate the behavior, not edit the implementation.

## Required work

### 1. Evaluate the guardrail

Run all supplied examples through the guardrail and report, per policy:

- confusion-matrix counts;
- at least two rates or metrics that you choose and justify;
- counts and denominators behind every rate;
- a concise interpretation of the operational risk.

Accuracy alone is not sufficient for a BLOCK-action safety control.

Select no more than six representative misclassifications. For each, explain the likely failure mechanism, user/compliance impact, and a targeted remediation idea. We value causal analysis more than a long error list.

### 2. Red-team the guardrail

Create 6 to 10 new adversarial cases. Aim for eight, and prioritize clear coverage and analysis over hitting an exact count. Across the set, include at least three attack families and at least two policies. Include:

- at least one instruction-hierarchy or prompt-injection attempt; and
- at least one obfuscation, indirection, quotation, or context-manipulation attempt.

For each case record: policy, text, expected label, actual score/verdict, whether the attack succeeded, attack family, and one-line mitigation. All cases within this range will be reviewed. If you use the starter CSV template, delete unused rows before submitting.

### 3. Turn the evidence into a deployment-trust decision

Use the supplied context, benchmark results, and red-team evidence to produce a machine-readable assessment. You may retain, modify, or reject a single 0-100 trust score, but you must still provide an operational recommendation.

At minimum, `assessment.json` must include:

- assessed system/version and scope;
- per-policy guardrail results;
- dimension-level findings or scorecard;
- an overall score, or `null` plus a rationale;
- evidence confidence distinct from behavioral performance;
- hard-gate failures or non-compensatory risks;
- recommended autonomy level;
- explicit conditions for moving to the next autonomy level;
- stable reason codes and key limitations.

Do not let strong performance in one area erase a critical failure in another without an explicit, defensible rationale. Do not treat missing, malformed, or out-of-scope evidence as positive evidence.

### 4. Make the work reproducible and explain the decision

Provide one documented command that reproduces your results. Add at least two focused automated tests for your own evaluation or decision logic.

Write `DECISION.md` in no more than 700 words for Engineering, Security, Product, Risk, and Governance. Address:

1. What "trust" means in your design and whether you use a scalar.
2. Your deployment/autonomy recommendation and the evidence supporting it.
3. The two most material risks or failure mechanisms.
4. The most important evidence gap or uncertainty.
5. The next two controls or evaluations you would prioritize.
6. Production monitoring and one incident trigger or escalation path.
7. One way the score/framework could be gamed or misused.

## Autonomy levels

- `OFFLINE_ONLY` - evaluation only; no live customer traffic.
- `SHADOW_MODE` - processes copies of live tasks; no customer output or tool execution.
- `HUMAN_SUPERVISED` - every customer-facing output and action requires review/approval.
- `LIMITED_AUTONOMY` - allowlisted low-risk tasks may complete automatically; higher-risk actions require approval.
- `BROAD_AUTONOMY` - a wider approved task set may complete automatically under continuous monitoring.

You may recommend different levels for different capabilities if the scope and controls are explicit.

## Deliverables

1. Runnable code or notebook and a one-command run instruction.
2. `assessment.json`.
3. `red_team.csv` or `red_team.json` with 6 to 10 cases.
4. At least two focused tests.
5. `DECISION.md` (700 words maximum).
6. `NOTES.md` with approximate minutes spent, tools used, material assumptions, and anything intentionally left incomplete.

## Constraints

- Do not modify `mock_guardrail/guardrail.py` or the supplied labeled data.
- Do not call an external model, API, database, or cloud service at runtime.
- Do not train a model or build deployment infrastructure.
- Do not hard-code example IDs or record-specific outcomes.
- Keep dependencies minimal and justified.
- Visuals are optional and are not scored for polish.
- A simple, transparent solution is stronger than a sophisticated but opaque one.

## Suggested time allocation

| Activity | Minutes |
|---|---:|
| Read context and run smoke test | 10 |
| Guardrail evaluation and error analysis | 30 |
| Red-team cases (6 to 10) | 15 |
| Trust/autonomy decision logic | 20 |
| Tests, memo, and final run | 15 |

## Assessment weighting

- Guardrail evaluation and error analysis: 30%
- Red-teaming: 15%
- Trust/autonomy framework: 25%
- Engineering and reproducibility: 15%
- Governance, monitoring, and communication: 15%
