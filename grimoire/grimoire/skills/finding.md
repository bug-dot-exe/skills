The output of our security result will be a set of findings.

As grimoire is [[summon]]ed a directory structure will be set up for the findings that you might discover.

You can write issues yourself or have grimoire write them for you, you can also collaborate and leverage grimoire to review your findings.

 > [!warning]
 >  You're responsible for your findings.
 >  
 >  Agents make mistakes, always perform a very thorough review of references/ proof of concepts/ etc. 
 
## Draft

Grimoire has a skill that helps with drafting issues. 

The drafting skill essentially builds on the [[triage]] skill, which constructs context and builds an understanding of the flaw at hand. It is often also the case that there is a [[proof of concept]] that also provides very useful insights for the construction of the actual finding.

## Review

Grimoire also has a skill to allow you to review findings.

This skill performs an analysis of the writing and reviews:
* best practice conformance
* clarity
* accuracy (fact check of quotes and claims)
* issue validity (using the [[familiar]])
* potential useful references

The review skill will leverage the [[librarian]] to automatically find similar findings, documentation related to the discovered issue, or even blog posts related to the subject. This provides a significant value add.

The user is presented with a comprehensive review and recommendations and asked whether they would like to automatically update the finding.

## Duplicate Detection

It is often the case that you have issues that are duplicate or that could be merged.

Grimoire has a skill which compares all your findings in order to find such opportunities. In general it will identify two classes: duplicate and similar.

*Duplicate* findings describe the exact same issue, while *similar* findings often have a slightly different / expanded scope. A good rule of thumb is that you can delete one of a pair of duplicate findings without losing information, you can not do the same for findings which are *similar*.

The duplicate detection skill can automatically delete duplicates and merge findings but always needs user confirmation before doing so.

## Utilities

The finding skill also comes with a couple of utility scripts which allows agents to efficiently search through the existing findings. 

The frontmatter contains a couple of useful fields for such searches and can be super helpful in finding related issues.
## Finding Best Practices

### Title
The title should be concise but give a clear idea of "where" and "how" there is a flaw and if possible it should also communicate "what" it allows an attacker to do. 

Example:
```
The backend route UPDATE /user does not perform authentication

or 

Account takeover enabled by lack of authentication in backend route UPDATE /user

never:

Missing authentication

or 

Account takeover

or 

Incorrect backend implementation
```

### Description

Sometimes the title would get too large if we fit all relevant information. The first line / paragraph of the description should fill in the gaps.

The description section should give a solid understanding of what components are affected and how. It is also really important to convey impact, and high level limitations (e.g. privileges required, prerequisite conditions, etc). The severity estimation of the issue and title are just an initial indication. Using the description of the issue any reader should be able to fully understand the threat imposed. 

The description should not get to large or complex. Use the details section where necessary.

### Details

The details section is where the technical deep dive happens. 

In case of complex exploits the details section might explain the exploits steps. 

### Recommendation

The recommendation should provide an objective and clear resolution strategy.

A recommendation should **never** suggest non-trivial code changes. It is acceptable suggesting adding comments or using a different function. It is not acceptable to provide a whole complex implementation strategy. Security Researchers are unbiased external reviewers, by suggesting complex implementations we become biased. 

If there is no obvious simple solution then it is okay to suggest that the design space for a solution to the flaw is too large and out of scope for this report.

### General

Issue findings are **self-contained**. This means that a reader needs to be able to fully comprehend the issue by just reading the finding. As a result we should include code snippets to the vulnerable code where needed. Though concepts such as re-entrancy are assumed to be well known, we can not assume that the reader knows everything. It's important to provide background where necessary with relevant citations.

Where possible we should always **provide references** to similar findings, and references to documentation which might be relevant with respect to the finding. The [[librarian]] is a perfect agent to help with this process.

Findings should always be **fact checked**, we can't ever have a case where we refer to a best practice or issue that does not actually exist.

## Structure 

```markdown
---
title: The title of your vulnerability
severity: an estimation of severity
type: the type of flaw (e.g. re-entrancy, dos or memory corruption)
context: a list of files related to this finding (potentially with line numbers)
---

## Description

[a description of the vulnerability]

## Details [optional]

## Proof of Concept

@the-poc-file

## Recommendation

[a concise recommendation]

## References [optional]
[1] example reference
```

## Notes
* The skill allows drafting issues but many researchers prefer writing their own issues. You can ask grimoire to just set up the template for you when you find a new issue.
* Even if you like writing issues completely manually it is still worthwhile using the finding review skill. It serves as a thorough fact check and often suggests useful resources to reference.