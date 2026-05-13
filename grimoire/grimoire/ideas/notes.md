# Grimoire Notes 

## Roadmap 

skills:
* triage 
* proof of concept   
* identify
    * maybe this skill needs to be split up (e.g. there could be a skill for building architectural context)
* context 
* scoping 
* flow
* back-pressure and automation
  * semgrep
  * codeql 
  * slither
* finding
* report 
* enscribe - build detection modules / knowledge base to help surface issues in future audits 

agents:
* sigil     (general sub-agent)
* librarian (fetches external documentation where relevant)
* imp       (reviews findings from external audits that might provide relevant information)
* scribe    (manages the personal spellbook)

grimoire:
* a guide about how to use the skills and agents that make up grimoire
    * this could also be a series of blog posts 

alchemy:
* set of tools and configurations around the skills and agents 
* I'm thinking about centering this around pi which is aimed at being extensible
* can build features like alloyed agents 

It might also be interesting to look at context engineering in relation to the skills and agents.

---

* many skill collections are opinionated and there is a learning curve 
* grimoire is essentially the same, but it would be good to enable compatibility, or look for ways to enable it
* It would be nice to have an idea about how grimoire should integrate with external knowledge bases such as the research that has been done by kaden. 
* Also, the scribe functionality is kind of close to something that you could build into an automatically learning agent pipeline. Something that just consumes the latest audit reports and potentially does a differential analysis to see how it needs to update itself to be able to detect the same bugs.
* How does consolidation work between global scribe artifacts and local / project specific scribe artifacts?
* I would like people to be able to change and or improve their local copy of grimoire so it adapts to their style of working. Not entirely sure how to structure that when grimoire is a plugin.

