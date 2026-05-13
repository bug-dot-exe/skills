import { execSync } from "node:child_process";
import type { GitStatus } from "./types.js";

let cachedStatus: GitStatus | null = null;
let cacheTime = 0;
let cachedBranch: string | null | undefined = undefined;
const CACHE_TTL = 1000;

function fetchGitStatus(branch: string | null): GitStatus {
  const result: GitStatus = { branch, staged: 0, unstaged: 0, untracked: 0 };

  try {
    const output = execSync("git status --porcelain", {
      encoding: "utf-8",
      timeout: 2000,
      stdio: ["pipe", "pipe", "pipe"],
    });

    for (const line of output.split("\n")) {
      if (!line) continue;
      const x = line[0];
      const y = line[1];
      if (x === "?" && y === "?") result.untracked++;
      else {
        if (x && x !== " " && x !== "?") result.staged++;
        if (y && y !== " " && y !== "?") result.unstaged++;
      }
    }
  } catch {
    // Not a git repo or git not available
  }

  return result;
}

export function getGitStatus(branch: string | null): GitStatus {
  const now = Date.now();
  if (cachedStatus && now - cacheTime < CACHE_TTL) {
    // Update branch from footer data even if using cached counts
    return { ...cachedStatus, branch: branch ?? cachedStatus.branch };
  }

  cachedStatus = fetchGitStatus(branch);
  cacheTime = now;
  return cachedStatus;
}

export function invalidateGitStatus(): void {
  cachedStatus = null;
  cacheTime = 0;
}

export function invalidateGitBranch(): void {
  cachedBranch = undefined;
}
