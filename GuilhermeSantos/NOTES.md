# Submission Notes

## Minutes spent

_Total time spent on this exercise:_ ~120 minutes
_Where I was at the 90-minute mark:_ starting step 6 — the core analisys and assumptions were already generated , so after the 90 minutes I was validating the pipeline end-to-end, creating an automated code and drafting DECISION.md and Notes.md.

## Tools used

<!-- List IDEs, AI assistants, libraries, scripts, etc. -->

- **VS Code** with Python as the development IDE.
- Prototyped the analysis in a **Jupyter notebook** (`evaluation.ipynb`) first to explore the data and validate the logic, then consolidated it into a reproducible **`solution.py`** 
- **Microsoft 365 Copilot** to read the brief PDF and walk through the steps in more detail, making sure I didn't miss any requirement.
- **GitHub Copilot** to speed up the analysis — scaffolding functions, building the metrics/trust-model logic, and converting the notebook work into `solution.py`.

## Material assumptions

<!-- Key assumptions that shaped your analysis or design decisions. -->

- **Autonomy ladder** (OFFLINE → SHADOW → HUMAN_SUPERVISED → LIMITED → BROAD) is driven by hard-gate outcomes, PII safety, and adversarial bypass rate.
- The provided labeled datasets are treated as representative of the in-scope traffic, even though they are small and English-dominant.

## Intentional omissions

<!-- What you deliberately left out, and why. -->
- **No calibrated probabilities or statistical confidence intervals** — the sample is too small (n=88, ~20–24 rows/policy) to justify them; I flagged this as the main evidence gap instead.
- **Limited red-team suite (8 cases)** — enough to demonstrate the bypass patterns (injection, obfuscation, PT-BR, PII-format evasion), not to produce a statistically robust bypass rate.
- **No real multilingual (PT-BR) evaluation** — called out as a gap rather than measured, since labeled PT-BR data wasn't available.
- **Time was the main limiting factor.** I really enjoyed the case, but there was a lot of information to produce. At a certain point I had to lean more into "vibe coding" and validating the output (moving fast with Copilot and iterating) than deep from-scratch construction, so I wouldn't blow the time budget. With more time I'd like to automate more de desisions, than it could be reused on every analisys, I mean I had only to set the constraint and it could do the entire risk assessment.
