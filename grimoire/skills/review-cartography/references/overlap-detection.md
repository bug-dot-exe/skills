# Overlap Detection

When reviewing a cartography file, overlaps with other flows indicate potential duplication
that degrades agent performance by splitting context across multiple files.

## What Counts as Overlap

### Shared Components

A "shared component" is an exact file path match between two flows' **Key Components** sections.
Only the path matters — role descriptions are ignored for matching purposes.

Entry Points and Flow Sequence file references are not counted. Only Key Components paths,
because these represent the core files that define a flow.

### Calculating Overlap Percentage

```
overlap = shared_components / max(components_A, components_B)
```

Use `max()` not `union()` — this catches subset flows where a small flow is entirely
contained within a larger one.

**Example:** Flow A has 8 components, Flow B has 5. They share 3 components.

```
overlap = 3 / max(8, 5) = 3 / 8 = 37.5% — below threshold
```

## Thresholds

| Percentage | Action |
|------------|--------|
| <20% | Normal. Flows share some infrastructure (database client, auth middleware). No action needed. |
| 20-40% | Note in review summary. Significant shared infrastructure but may represent genuinely different activities. |
| >40% | Flag to user. Suggest `[[gc-cartography]]` for potential merging. |

## When Overlap Is Acceptable

Not all overlap warrants merging. Overlap is expected when:

- Flows share a common entry point (e.g., API gateway) but diverge immediately
- Flows share infrastructure components (database client, auth middleware) used by many flows
- Flows represent different security concerns in the same codebase area

## When to Suggest gc-cartography

Overlap likely indicates duplication when:

- Two flows describe the same activity from different perspectives
- One flow is a strict subset of another (all components contained)
- Flows share >40% of components AND have similar descriptions
- Three or more flows form an overlap cluster (A overlaps B, B overlaps C)

## Detection in Practice

During step 4 of the review-cartography workflow:

1. Read frontmatter of all other cartography files in the index
2. For the flow under review, extract its Key Components paths
3. For each other flow, extract its Key Components paths
4. Calculate pairwise overlap percentage using the formula above
5. Report any pairs exceeding 40% as candidates for `[[gc-cartography]]`
6. Note 20-40% pairs in the review summary as informational

The `scripts/find-overlaps.sh` script automates steps 2-6 across all flows.
