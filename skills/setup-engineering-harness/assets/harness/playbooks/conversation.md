<!-- engineering-harness:installer-owned -->
# Objective decisions

Ask only when the answer can change product behavior, architecture, cost, security, an external
contract, or a hard-to-reverse choice. First resolve facts available from the Project.

Batch independent questions once. Use:

```text
Facts
- <observation with path, symbol, config key, exact version, or command evidence>

Questions
1. <neutral question>
   A. <real option: effect and tradeoff>
   B. <real option: effect and tradeoff>
   C. <real option: effect and tradeoff>

Recommendations
1. <choice> — <explicit criteria and evidence-based reason>
```

Apply the same comparison dimensions to every option. Do not label an option “recommended,” make
straw alternatives, hide costs, or mix the recommendation into the choices. If no answer is
needed, proceed with a stated, reversible assumption.
