A proof of concepts is an incredibly useful artefact.

In security research you're often working with an incomplete understanding of a system. This is the case because it's both impossible and not time efficient to build such an understanding. An unfortunate side-effect is that you'll sometimes believe that you've identified a bug, even though it's actually a false positive.

Additionally, though your bug might be valid it is possible that the development team disagrees with your assessment. Bugs often arise from complex situations with incorrect assumptions. As a result, initial disagreements on validity are not uncommon. Especially for bug bounties.

A proof of concept helps create clarity both for you and for the developers triaging your findings.

Unfortunately, writing a proof of concept takes time and effort. Time and effort which could've been put towards finding more bugs. 
## Agentic - Proof of Concept development

Coding is probably the most successful application area for agents.

That agents are good at helping you write a proof of concept should be no surprise. So what then does grimoire add that agents don't already have?

Opinions!

It is relatively straightforward to have an agent write proof of concepts for your findings. Just pipe in your finding report and say "please give me a testcase to demonstrate X". 

This will work in 60%, the other 40% are cases where the agent needs some input on approach, dependencies, etc. You'll often also find yourself providing some suggestions or tweaks to the resulting PoC.

Grimoire's `proof-of-concept` improves one-shot success rate to 90% by providing an opinionated structure to proof of concept development.

## Infrastructure

Some bugs can be demonstrated using a simple testcase.

Others are more elaborate. You might need to pull interfaces from etherscan, setup a flashloan, or want to set up a fork test to demonstrate an end-to-end exploit. 

In the case of *smart contract* bugs you often want to demonstrate monetary impact. The Grimoire `proof of concept` skill makes sure your agent already knows that this is important, and will add verbose logging where necessary to demonstrate such impact.

Today Grimoire is most extensively developed for web3 security research, as this is where I'm currently most active. However, it is aimed at being a general framework for software auditing. 
