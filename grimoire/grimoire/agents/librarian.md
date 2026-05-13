The librarian is an agent that helps you get info from external codebases, knowledge-bases and documentation.

There are two ways to interact with the librarian. You can ask it a directed question `Hey can you explain how function XYZ should be called? Does it ensure ABC?`. You can also ask it to generically study an external subject `study the ERC4626 specification, find me best practices and common vulnerabilities` with the goal of priming context for future questions.

In general you'll probably want to use the first method as it provides for a cleaner context for the main thread. However sometimes this is desired so it's up to you!

The librarian should automatically be used whenever there is a need for information that can not immediately be found in the codebase. It's better for agents to use the librarian than to guess based on their own knowledge.

The librarian is extremely detail oriented and will only produce claims backed up with references. It's goal is never to provide answers on it's own, but to provide answers based on external data sources. 
## Code Retrieval and Cache

Sometimes the librarian will find it useful to access external codebases, to facilitate efficiency the librarian can clone repositories and store them locally in `~/.grimoire/librarian/cache`. This allows the librarian to explore external codebases with the same efficiency that local code search provides. 

Not every integration or dependency will be pulled by the librarian, it only does so when it determines that it is necessary for a query that it was asked to answer.

To prevent this cache from polluting your hard disk the librarian provides the `librarian-clean-cache` skill which clears this cache directory.

## External Knowledge Bases

Many researchers are building quite interesting knowledge bases, take [smart-contract-vulnerabilities](https://github.com/kadenzipfel/smart-contract-vulnerabilities) for example.

These can provide useful information in different scenarios:
1. Contextual Suggestions - A researcher might ask whether there are any relevant best practices / (flaws) related to a piece of code that they are reviewing.
2. References - It can be helpful to provide references when writing up a finding.

To facilitate this the `.grimoire/librarian/library` directory can hold many different repositories with useful information. 

### Indexing

At the root of the `library` directory there is a `libraries.yaml` file which provides information on all the libraries that the librarian can access. 

It also provides information on the type of library and source allowing the librarian to automatically fetch updates and prevent staleness.

```yaml
libraries:
	smart-contract-vulnerabilities:
		type: git
		source: git@github.com:kadenzipfel/smart-contract-vulnerabilities.git
```

### Vector Search

Though not implemented yet we're actively researching efficient information retrieval methods including vector databases.

### Initialize

The user can use the `librarian-initialize` skill to automatically setup the library directory with an empty libraries yaml file and an empty cache directory. 

The initialize skill also helps you upgrade in the future. The skill will automatically identify existing librarian initializations and upgrade the existing structure where necessary.

### Add Library

The user can use the `modify-library` skill to add, remove or change a library. This single skill will trigger whenever you ask the librarian to change the grimoire libraries.

You can add different types of libraries, for example:
* git
* symlink 

The skill will automatically validate that the references provided point to a valid repository / directory / etc.

## Sources

Librarian usually builds on the following sources:
* context7
* exa
* solodit
	* https://github.com/marchev/claudit
* various web3 security knowledge bases
	* kaden: https://github.com/kadenzipfel/smart-contract-vulnerabilities
* github
	* gh cli skill dependency
* [[personal grimoire]]

## Resources
* ampcode - https://ampcode.com/manual#librarian
* pi librarian skill - https://github.com/superresistant/librarian