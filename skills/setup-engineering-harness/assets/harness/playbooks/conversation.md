<!-- engineering-harness:installer-owned -->
# Requirement alignment

Resolve facts available from the Project before asking the user. Ask when an answer can
materially change product behavior, architecture, cost, security, an external contract, or a
hard-to-reverse choice.

Batch independent questions in one concise group. Ask dependent follow-ups only after the
earlier answer changes the available options. Do not force a one-question-at-a-time ritual.

When options help, compare each on the same dimensions:

```text
Facts
- <repository or product fact and its evidence>

Questions
1. <neutral question>
   A. <real option — effect and tradeoff>
   B. <real option — effect and tradeoff>

Recommendation
- <choice> — <criteria and evidence-based reason>
```

Adapt this shape to natural conversation; it is not a required form. Keep recommendations
separate from neutral choices, avoid straw alternatives, and explain what each answer changes.
If no answer is needed, proceed with a stated reversible assumption.

Accept ordinary language such as “yes,” “okay,” “do that,” or its equivalent in the user's
language when the referent is clear. Ask for clarification only when the referent is genuinely
ambiguous or the action needs new authority.
