The checks skill enables pure agentic flaw detection.

Checks provide a simple file structure describing vulnerability patterns that an agent can discover in a codebase. They essentially describe starting points based on common mistakes and best practices that can be used to find flaws and vulnerabilities.

Checks should be simple and straightforward. They're not meant to provide extensive documentation on different flaws. For example, you might have a check which provides a list of things to check whenever an ERC 4626 vault is encountered. The check itself should not provide too much context on ERC 4626, just what to check. Checks can leverage the [[librarian]]  agent to provide more context when needed.

### Attention

Attention is an important factor so checks should be limited in context. How to determine when a check should be split up is difficult.

An example of when splitting up is useful is a set of checks which explores rounding errors. The identification of rounding. However, most often rounding even in the wrong direction is benign. As a result you might want to have agent automatically check different ways in which rounding might be problematic. 

Though the checklist might be simple and have elements such as "determine if rounding is used in regards to a deposit and whether this might lead to an inflation attack". The actual reasoning process involved in evaluating that option is not.

In such a case it's better to have multiple checks.

> [!info] 
> Grimoire might implement some form of co-ordination between checks or hirarchical checks in the future to be more token efficient.

### Simplicity

It is enticing to produce super complex checks that find lots of cool bugs.

It is much more worthwhile having many simple checks that filter out common mistakes and bugs. 

## File Structure
The following is an example check:

```markdown
---
name: debug assertions
description: Flags security critical debug assertions which should be regular assertions.
languages: rust
severity-default: low
confidence: medium
tools: [Grep, Read]
---

Look for these patterns:

- debug_assert!(...);
  
Not all debug_assert! usage is problematic. Assess whether usage falls in one of two categories:
1. asserting a known and assumed invariant
2. performing essential input / state validation

If (1) might be the case adjust severity to informational.

If (2) seems to be the case then determine potential impact and adjust severity accordingly.
```

## Resources
* ampcode.com/manual#code-review