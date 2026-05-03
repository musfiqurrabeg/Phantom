---
name: mythos-thinking
description: >
  Use when the problem is complex, hard, or high-stakes. Triggers on: system design,
  AI agent architecture, agentic AI, multi-agent pipelines, LLM engineering, RAG systems,
  complex code (debugging, refactoring, architecture), strategy (business, career, freelance),
  security research, bug bounty planning, deep technical analysis, trade-off decisions,
  "think hard", "think deep", "go deep on this", "mythos mode", or any problem where
  a single-pass answer would be shallow. Do NOT use for simple factual lookups, greetings,
  or one-liner code snippets. When in doubt — if the problem has real stakes — use this skill.
metadata:
  category: reasoning
  triggers: complex, strategy, agent, architecture, deep, think hard, system design, agentic, debug, trade-off, mythos
---
 
# Mythos Thinking
 
Simulates the Recurrent-Depth Transformer (RDT) reasoning loop from the OpenMythos architecture.
Instead of answering in one pass, Claude runs multiple internal reasoning loops — each one refining,
challenging, and improving the previous — before converging on a final answer.
 
Harder problems get more loops. Simple-but-complex problems get fewer.
 
---
 
## Core Principle
 
```
Input → [Loop 1: Understand] → [Loop 2: Analyze] → [Loop N: Converge] → Output
```
 
Each loop is a full reasoning pass. Like OpenMythos's recurrent block:
- The **original problem (e** — encoded input) is re-injected at every loop iteration unchanged
- The **hidden state (h)** evolves — each loop builds on the last
- **ACT halting** — loop exits when reasoning has converged (no new insight gained)
- **LoRA-style adaptation** — each loop has a different "role" (understand → challenge → refine → synthesize)
---
 
## Loop Depth Guide (Adaptive)
 
| Problem Type | Loop Depth | Example |
|---|---|---|
| Moderate complexity | 2–3 loops | Refactor a function, explain a concept deeply |
| High complexity | 4–5 loops | System design, agent architecture, strategy |
| Critical / adversarial | 6+ loops | Security flaws, irreversible decisions, novel architectures |
 
**User control:**
- "think hard" → 4 loops minimum
- "think deep" / "go deep" → 5+ loops
- "mythos mode" → max depth, show all loops
- "quick take" → override to 1–2 loops even on complex topics
---
 
## The Loop Structure
 
Run each loop internally. Label them clearly. Each loop has a fixed role:
 
### Loop 1 — Understand
> Re-read the problem. What is actually being asked? What are the constraints? What would a bad answer look like?
 
### Loop 2 — First Principles Analysis
> Break it down from scratch. What are the core components, trade-offs, unknowns? Don't optimize yet — map the terrain.
 
### Loop 3 — Challenge
> Attack your own Loop 2 thinking. Where is it wrong, incomplete, or naïve? What edge cases break it? What assumptions are hidden?
 
### Loop 4 — Refine
> Incorporate the challenges. Build the improved model. This is where correctness gets locked in.
 
### Loop 5 — Synthesize
> Compress everything into the clearest, most actionable form. Remove anything that doesn't serve the answer.
 
### Loop 6+ — Adversarial / Domain-Specific
> For security: attack surface analysis. For agents: failure mode enumeration. For strategy: second-order effects.
> Only run if the problem genuinely requires it.
 
---
 
## Output Format
 
**For most problems (loops 2–5):**
 
Show a collapsed loop summary, then the final answer.
 
```
━━━ MYTHOS LOOP ━━━
▸ L1 [Understand]: {1-line summary of what was clarified}
▸ L2 [Analysis]:   {1-line summary of the core breakdown}
▸ L3 [Challenge]:  {1-line — what assumption was killed}
▸ L4 [Refine]:     {1-line — what changed}
▸ Converged at Loop {N}
━━━━━━━━━━━━━━━━━━━
 
{Final answer — clean, direct, no loop language}
```
 
**For "mythos mode" (user explicitly requests full depth):**
 
Show each loop in full before the final answer.
 
```
━━━ MYTHOS LOOP — FULL DEPTH ━━━
 
[LOOP 1 — UNDERSTAND]
{Full reasoning}
 
[LOOP 2 — FIRST PRINCIPLES]
{Full reasoning}
 
...
 
[CONVERGED — LOOP N]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 
{Final answer}
```
 
---
 
## ACT Halting Rule
 
Stop looping when:
- A new loop adds no insight the previous didn't already cover
- The answer has stabilized (same conclusion, just different words)
- The problem is fully mapped with no remaining unknowns
Never run loops for the sake of hitting a number. Converge early if the problem converges early.
 
---
 
## LTI Stability Rule (Anti-Drift)
 
At every loop, re-read the original problem before continuing.
The encoded input **e** is always present. Don't let the reasoning drift into solving a different problem.
 
If you catch yourself solving something adjacent — reset to the original problem statement.
 
---
 
## Examples of When to Trigger
 
**YES — use this skill:**
- "Design a 6-agent bug bounty pipeline in Python"
- "Should I position my Upwork profile around SST or Google Ads?"
- "Debug why my FastAPI RAG system is losing context across sessions"
- "Architect a multi-tenant sGTM setup for enterprise clients"
- "Think hard about whether I should pursue OSCP before eJPT"
- "What's wrong with this approach to MoE routing?"
**NO — don't use this skill:**
- "What's the syntax for a Python list comprehension?"
- "Hey what's up"
- "What does RMSNorm do?" (one-pass explanation is enough)
- "Translate this to Spanish"
---
 
## Common Mistakes to Avoid
 
| Mistake | Fix |
|---|---|
| Running all 6 loops on a 2-loop problem | Use ACT halting — exit when converged |
| Showing loop headers but not actually reasoning differently per loop | Each loop must have a distinct cognitive role |
| Drifting from the original question by Loop 3 | Re-anchor to **e** (original problem) every loop |
| Making the loop summary longer than the final answer | Summary is 1 line per loop, that's it |
| Using mythos format on simple questions | This skill does NOT trigger on simple queries |
 