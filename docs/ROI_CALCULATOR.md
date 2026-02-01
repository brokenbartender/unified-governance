# ROI Calculator

## Inputs
- Number of governed applications
- Number of policies
- Monthly evaluations
- Average audit hours per quarter
- Average compliance engineer hourly rate

## Output
- Estimated audit hours saved
- Estimated cost savings (audit + remediation)
- Estimated risk reduction (policy drift + evidence integrity)

## Default Model
- Audit hours saved per quarter: `audit_hours * 0.35`
- Policy error reduction: `policy_count * 0.15`
- Evidence export prep time reduced by 70%

## Live Demo Output
Example (10 apps, 80 policies, 250k evals/month, 120 audit hours, $160/hr):
- Audit hours saved: ~42 hrs / quarter
- Cost savings: ~$6,720 / quarter
- Annualized savings: ~$26,880

Use with `docs/RISK_REDUCTION_REPORT.md` for procurement justification.
