import type { Theme, ThemeColor } from "@mariozechner/pi-coding-agent";

/** Theme color — either a pi theme color name or a custom hex color */
export type ColorValue = ThemeColor | `#${string}`;

/** Semantic color names for grimoire segments */
export type SemanticColor =
  | "grimoire"
  | "model"
  | "path"
  | "git"
  | "gitDirty"
  | "gitClean"
  | "thinking"
  | "context"
  | "contextWarn"
  | "contextError"
  | "cost"
  | "tokens"
  | "separator";

/** Color scheme mapping semantic names to actual colors */
export type ColorScheme = Partial<Record<SemanticColor, ColorValue>>;

/** Segment identifiers */
export type SegmentId =
  | "grimoire"
  | "model"
  | "thinking"
  | "path"
  | "git"
  | "context_pct"
  | "cost"
  | "cache_read";

/** Segment options */
export interface SegmentOptions {
  model?: { showThinkingLevel?: boolean };
  path?: { mode?: "basename" | "abbreviated" | "full"; maxLength?: number };
  git?: { showBranch?: boolean; showStaged?: boolean; showUnstaged?: boolean; showUntracked?: boolean };
}

/** Context passed to segment render functions */
export interface SegmentContext {
  model: { id: string; name?: string; reasoning?: boolean; contextWindow?: number } | undefined;
  thinkingLevel: string;
  usageStats: UsageStats;
  contextPercent: number;
  contextWindow: number;
  autoCompactEnabled: boolean;
  usingSubscription: boolean;
  git: GitStatus;
  options: SegmentOptions;
  theme: Theme;
  colors: ColorScheme;
}

/** Usage statistics */
export interface UsageStats {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
  cost: number;
}

/** Git status data */
export interface GitStatus {
  branch: string | null;
  staged: number;
  unstaged: number;
  untracked: number;
}

/** Rendered segment output */
export interface RenderedSegment {
  content: string;
  visible: boolean;
}
