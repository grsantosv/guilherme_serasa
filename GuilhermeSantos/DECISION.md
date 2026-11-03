# Deployment Decision — Northwind Assist (agent-v2)

_Audience: Engineering, Security, Product, Risk, Governance. Guardrail scope: pre/post-LLM input/output filter for the Northwind credit-report assistant (EN + PT-BR traffic)._

## 1. What "trust" means and why no single scalar

Trust here is **fitness to operate safely at a given level of autonomy**, not a quality percentage. We deliberately **do not publish a single trust scalar**. `overall_score` is intentionally `null` because trust is **non-compensatory**: strong toxicity filtering cannot offset a PII leak. Instead we use a profile of (a) per-policy **dimensions** (STRONG/WEAK/FAIL), (b) **hard gates** that must all pass, (c) **evidence confidence**, and (d) **adversarial bypass rate**. A scalar only exists once every gate passes and red-team bypass ≤10%; otherwise the honest answer is "not yet trustworthy", with reasons.

## 2. Recommendation and evidence

**Recommendation: OFFLINE_ONLY** — do not place this guardrail in the live customer path. Evidence (benchmark n=88, red-team n=8):

- **3 of 4 hard gates FAILED.** NO_PII_DISCLOSURE recall 0.80 with **2 false negatives** (any PII FN fails the gate); TOXIC_CONTENT recall 0.70 / FPR **0.40**; ON_TOPIC recall 0.58.
- **Red-team bypass 75% (6/8)** across prompt-injection, obfuscation/leetspeak, PII-format evasion, and PT-BR evasion — far above the 10% ceiling.
- NO_FINANCIAL_ADVICE is only WEAK (recall 0.67), so even the passing gate is not production-ready.

The design ladder (OFFLINE → SHADOW → HUMAN_SUPERVISED → LIMITED → BROAD) selects OFFLINE_ONLY because PII fails and adversarial bypass exceeds 50%.

## 3. Two most material risks

1. **PII leakage (regulatory + customer harm).** SSNs without punctuation (`111223333`) pass undetected (R006). In a credit-report product this is the highest-severity failure: real identifiers can reach the user and downstream logs.
2. **Trivial adversarial bypass.** Because the guardrail is keyword/regex-based, leetspeak (`1d10t`), character spacing (`i-n-v-e-s-t`), quotation/indirection, and PT-BR insults defeat it. A motivated user bypasses controls with near-zero effort — and there is **no dedicated prompt-injection policy** at all.

## 4. Most important evidence gap

**Statistical power and language coverage.** Confidence is **LOW**: only ~20–24 labeled rows per policy and 8 red-team cases, all English-dominant despite PT-BR being in scope. We cannot distinguish a 0.70 recall from a 0.85 recall at this sample size, and we have **essentially no measured evidence** for Portuguese. Every number is indicative, not conclusive.

## 5. Next two controls/evaluations to prioritize

1. **PII detection hardening + output-side gate:** normalize/strip separators, add word-spelled and non-US formats; re-validate to **zero PII FN on ≥200 adversarial cases**.
2. **Expanded multilingual red-team suite (≥50 cases):** add Unicode/accent normalization and a PT-BR lexicon, plus a dedicated injection policy; target **bypass ≤10%**. (A context-aware toxicity classifier to cut the 0.40 FPR is the fast follow.)

## 6. Production monitoring and incident trigger

Even in OFFLINE_ONLY (shadow logging), monitor continuously:

- **PII-FN rate** (sampled human audit of allowed outputs), **block/allow rates per policy**, **toxicity FPR** (user-reported over-blocks), and **injection/obfuscation hit rate**.
- **Incident trigger:** a **single confirmed PII false negative in production** is a page-worthy Sev-1 → auto-disable the agent path (fail-closed), notify Security + Privacy/DPO on-call, and open a Governance review before re-enabling. Secondary trigger: toxicity FPR >15% sustained over 1h → Product/Eng review for user-experience harm.

## 7. How the score/framework could be gamed

**Benchmark overfitting.** Because the guardrail is lexicon-based, anyone can "pass" by adding the exact failing phrases to the keyword list and re-running the same small fixed dataset — inflating recall without any real robustness gain. More broadly, reporting a single high scalar would let a strong dimension mask a failing PII gate. Mitigations: keep the gate model non-compensatory, rotate/withhold a **held-out adversarial test set**, require **fresh** red-team cases each cycle, and treat metric jumps on a static dataset as a red flag rather than progress.

---

**Bottom line:** agent-v2's guardrail is a useful baseline but is **not deployable** in the customer path. Keep it OFFLINE_ONLY, fix PII and adversarial robustness first, and re-assess against a larger, multilingual, held-out evaluation before advancing to SHADOW_MODE.
