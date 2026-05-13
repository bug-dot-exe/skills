In science common concepts are that of *falsifiability* and *verifiability*. These relates to the quality of a claim/hypothesis and whether it can easily be tested or (dis-)proven.

Falsification and verification are not the same, and their distinction is incredibly important when you're using an agent in auditing.

You can ask questions like: find me all locations in the code where user input is stored. (easy to disprove a claim by finding a counter-example)

You can also ask questions like: is there a location in the code that does input sanitation. (easy to prove a claim by checking the example given)

These are very different and you should pick your questions carefully!

## why?

Agents are smart but unreliable.

You'll encounter hallucinations, cheating and reasoning mistakes when you start to use agents. As a result we need to ask ourselves the question: how can we still use agents even if the agents are sometimes wrong?

The answer might seem obvious. Simply ask questions that lead to verifiable claims. 

> [!info]
> I use verifiability a bit different than how it is normally used. Often universal claims are falsifiable but not verifiable. In code there are a lot of universal claims that might be verifiable, but not trivially so. The verification of such a claim would involve a lot of effort and time. 
> 
> As a result the term trivial verifiability might be more appropriate, to indicate such claims that can be verified with little effort.

An example application of this principle:
```
good

Statement: There are no wolves in this town.
Counterexample: Here is a picture taken today of a wolf in this town.


bad

Statement: all animals in this town are dogs
Proof: pictures of a bunch of animals
```

A more code oriented example:
```
good

Statement: I found a formfield that might be vulnerable to XSS there is some escaping can you find me the code that performs the escaping and explain what measures it implements?
Counterexample: link to the code + explanation

bad

Statement: Can you find all locations where user input is displayed on the frontend without proper sanitisation
Proof: some code locations
```

Careful though!

A claim `this location uses sanitisation` is verifiable, the claim `only this location uses sanitisation` is not. It is super easy to fall in the trap of inadvertently assuming the second is valid, even though it is not.

## Not a Rule

Non verifiable questions are dangerous but can also be powerful.

Open-ended `find me all X` questions (who's answers will constitute *falsifiable claims*) can be used as a form of fuzzing. Identifying interesting locations for you to go and have a look at. Providing exploitation [[hypothesis]] for you to verify and potentially include in a report.

Be ware!

The auditing process is largely cognitive, and our brains like shortcuts. Treat the output to such questions as radioactive. Trust the agent to provide you with interesting data. Never trust it to provide you the correct answer to a question. 

## Autonomous Vulnerability Discovery

Note that this concept is not necessarily limited to co-auditing approaches.

An [[autonomous vulnerability discovery]] agent can also leverage these insights. In autonomous discovery processes it's worthwhile reaching for methods that apply [[backpressure]] (such as a semgrep / codeql rule) whenever *non trivially verifiable* claims are posed.
