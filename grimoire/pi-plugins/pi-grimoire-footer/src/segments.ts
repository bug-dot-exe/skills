import { basename } from "node:path";
import type { RenderedSegment, SegmentContext, SemanticColor } from "./types.js";
import type { SegmentId } from "./types.js";
import { fg, applyColor } from "./colors.js";
import { getIcons, getThinkingIcon } from "./icons.js";

function color(ctx: SegmentContext, semantic: SemanticColor, text: string): string {
  return fg(ctx.theme, semantic, text, ctx.colors);
}

function withIcon(icon: string, text: string): string {
  return icon ? `${icon} ${text}` : text;
}

function formatTokens(n: number): string {
  if (n < 1000) return n.toString();
  if (n < 10000) return `${(n / 1000).toFixed(1)}k`;
  if (n < 1000000) return `${Math.round(n / 1000)}k`;
  if (n < 10000000) return `${(n / 1000000).toFixed(1)}M`;
  return `${Math.round(n / 1000000)}M`;
}

// ═══════════════════════════════════════════════════════════════════════════
// Segment Implementations
// ═══════════════════════════════════════════════════════════════════════════

const SEGMENTS: Record<SegmentId, { render(ctx: SegmentContext): RenderedSegment }> = {
  grimoire: {
    render(ctx) {
      const icons = getIcons();
      return { content: color(ctx, "grimoire", `${icons.grimoire} grimoire`), visible: true };
    },
  },

  model: {
    render(ctx) {
      const icons = getIcons();
      let modelName = ctx.model?.name || ctx.model?.id || "no-model";
      if (modelName.startsWith("Claude ")) modelName = modelName.slice(7);
      const content = withIcon(icons.model, modelName);
      return { content: color(ctx, "model", content), visible: true };
    },
  },

  thinking: {
    render(ctx) {
      const level = ctx.thinkingLevel || "off";
      if (level === "off") return { content: "", visible: false };
      const icon = getThinkingIcon(level);
      const labels: Record<string, string> = {
        minimal: "min", low: "low", medium: "med", high: "high", xhigh: "xhigh",
      };
      const label = labels[level] || level;
      const content = icon ? `${icon} ${label}` : label;
      return { content: color(ctx, "thinking", content), visible: true };
    },
  },

  path: {
    render(ctx) {
      const icons = getIcons();
      const opts = ctx.options.path ?? {};
      const mode = opts.mode ?? "basename";
      let pwd = process.cwd();
      const home = process.env.HOME || process.env.USERPROFILE;

      if (mode === "basename") {
        pwd = basename(pwd) || pwd;
      } else {
        if (home && pwd.startsWith(home)) pwd = `~${pwd.slice(home.length)}`;
        if (mode === "abbreviated") {
          const maxLen = opts.maxLength ?? 40;
          if (pwd.length > maxLen) pwd = `…${pwd.slice(-(maxLen - 1))}`;
        }
      }
      return { content: color(ctx, "path", withIcon(icons.folder, pwd)), visible: true };
    },
  },

  git: {
    render(ctx) {
      const icons = getIcons();
      const opts = ctx.options.git ?? {};
      const { branch, staged, unstaged, untracked } = ctx.git;

      if (!branch) return { content: "", visible: false };

      const isDirty = staged > 0 || unstaged > 0 || untracked > 0;
      const branchColor: SemanticColor = isDirty ? "gitDirty" : "gitClean";
      const branchIcon = isDirty ? icons.branchDirty : icons.branch;
      let content = color(ctx, branchColor, withIcon(branchIcon, branch));

      const indicators: string[] = [];
      if (opts.showUnstaged !== false && unstaged > 0)
        indicators.push(applyColor(ctx.theme, "warning", `*${unstaged}`));
      if (opts.showStaged !== false && staged > 0)
        indicators.push(applyColor(ctx.theme, "success", `+${staged}`));
      if (opts.showUntracked !== false && untracked > 0)
        indicators.push(applyColor(ctx.theme, "muted", `?${untracked}`));

      if (indicators.length > 0) content += ` ${indicators.join(" ")}`;

      return { content, visible: true };
    },
  },

  context_pct: {
    render(ctx) {
      const icons = getIcons();
      const pct = ctx.contextPercent;
      const window = ctx.contextWindow;
      const autoIcon = ctx.autoCompactEnabled && icons.auto ? ` ${icons.auto}` : "";
      const text = `${pct.toFixed(1)}%/${formatTokens(window)}${autoIcon}`;

      let content: string;
      if (pct > 90) {
        content = withIcon(icons.context, color(ctx, "contextError", text));
      } else if (pct > 70) {
        content = withIcon(icons.context, color(ctx, "contextWarn", text));
      } else {
        content = withIcon(icons.context, color(ctx, "context", text));
      }
      return { content, visible: true };
    },
  },

  cost: {
    render(ctx) {
      const icons = getIcons();
      const { cost } = ctx.usageStats;
      if (!cost && !ctx.usingSubscription) return { content: "", visible: false };
      const display = ctx.usingSubscription ? "(sub)" : `$${cost.toFixed(2)}`;
      return { content: color(ctx, "cost", withIcon(icons.cost, display)), visible: true };
    },
  },

  cache_read: {
    render(ctx) {
      const icons = getIcons();
      const { cacheRead } = ctx.usageStats;
      if (!cacheRead) return { content: "", visible: false };
      const parts = [icons.cache, icons.input, formatTokens(cacheRead)].filter(Boolean);
      return { content: color(ctx, "tokens", parts.join(" ")), visible: true };
    },
  },
};

export function renderSegment(id: SegmentId, ctx: SegmentContext): RenderedSegment {
  const segment = SEGMENTS[id];
  if (!segment) return { content: "", visible: false };
  return segment.render(ctx);
}
