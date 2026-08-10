# DetectionLab governed engineering workflow

DetectionLab is a controlled detection-validation engineering lab and portable replay/validation framework. Repository contracts, the README, and implemented interfaces are authoritative.

## Authority and boundaries

README / repository contracts / implemented interfaces → assigned engineering objective → coding agent → reconnaissance → implementation → tests → self-correction → acceptance gate → evidence → human review.

Agents must inspect repository state before editing, avoid inventing missing requirements, preserve ingestion/normalization/schema/correlation/detection boundaries, and reuse existing components. Do not weaken tests, alter expected detections without explicit task authority, silently change validation semantics, or introduce SIEM, SaaS, streaming, database, connector, cloud, or autonomous SOC scope. Run the complete acceptance gate. Repair implementation defects autonomously. Stop only when a required product/design decision is genuinely undefined. Evidence must come from actual commands, not narrative claims.

## Procedure

RECONNAISSANCE → PLAN INSIDE AUTHORIZED GOAL → IMPLEMENT → TEST → INSPECT FAILURE → REPAIR → RETEST → ADVERSARIAL CHECK → ACCEPTANCE GATE → EVIDENCE → STOP

The canonical completion command is `python Pipeline/labctl.py gate`. No change is accepted until it passes.
