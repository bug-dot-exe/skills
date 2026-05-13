# GPTScan

Smart contract logic vulnerability detection using LLM-guided program analysis.

Source: https://github.com/GPTScan/GPTScan (ICSE '24 paper)

## Overview

GPTScan combines GPT with static program analysis to detect logic vulnerabilities in Solidity smart contracts. It uses a two-phase approach:
1. **Scenario matching**: GPT identifies whether a function matches a known vulnerability scenario (from YAML rule definitions)
2. **Static confirmation**: Program analysis confirms/filters GPT's candidates using call graphs, data flow, and static checks

## Vulnerability Rules (src/rules/)

Each YAML rule defines a vulnerability class with scenario descriptions, properties to check, and static confirmation criteria:

- **ApprovalNotClear** - Token approval not cleared after transfer
- **FirstDeposit** - First depositor share inflation attack (ERC4626-style)
- **Flashloan_Buy** - Flash loan used to manipulate buy operations
- **Flashloan_Price** - Flash loan price oracle manipulation
- **Flashloan_Vote** - Flash loan governance vote manipulation
- **FrontRun** - Front-running vulnerable operations
- **Slippage** - Missing or insufficient slippage protection
- **UnauthorizedTransfer** - Transfer without proper authorization checks
- **WrongOrder_Checkpoint** - Incorrect checkpoint update ordering
- **WrongOrder_Interest** - Incorrect interest calculation ordering

## Key Components

- `src/query_template.py` - GPT prompt templates for each vulnerability scenario
- `src/analyze_pipeline.py` - Main analysis pipeline orchestrating GPT + static analysis
- `src/tasks.py` - Task definitions and parallel execution
- `src/static_check.py` - Static analysis confirmation checks
- `src/antlr4helper/` - Solidity parser and call graph builder (ANTLR4-based)
- `src/chatgpt_api.py` - OpenAI API wrapper
- `src/whitelist.json` - Known-safe function signatures whitelist

## Usage as Reference

When auditing smart contracts, reference the vulnerability rules in src/rules/ for:
- Understanding common logic vulnerability patterns
- Checking if a function matches known vulnerability scenarios
- Using the static confirmation criteria to validate findings
- Leveraging the query templates as structured reasoning frameworks

## Prerequisites (if running GPTScan directly)

- Python 3.10+
- Java 17+ (for call graph JAR)
- solc-select with appropriate Solidity compiler version
- OpenAI API key
