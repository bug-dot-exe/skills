import type { ExtensionAPI, ReadonlyFooterDataProvider, Theme } from "@mariozechner/pi-coding-agent";
import type { AssistantMessage } from "@mariozechner/pi-ai";
import { visibleWidth } from "@mariozechner/pi-tui";

import type { ColorScheme, SegmentContext, SegmentId } from "./types.js";
import { renderSegment } from "./segments.js";
import { getGitStatus, invalidateGitStatus, invalidateGitBranch } from "./git-status.js";
import { ansi, getSepAnsi, getDefaultColors } from "./colors.js";
import { getSeparatorChars } from "./icons.js";
import { getVibe } from "./messages.js";

// ═══════════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════════

const SEGMENTS_LEFT: SegmentId[] = [
  "grimoire", "model", "thinking", "path", "context_pct", "cache_read",
];

const SEGMENT_OPTIONS = {
  model: { showThinkingLevel: false },
  path: { mode: "basename" as const },
  git: { showBranch: true, showStaged: true, showUnstaged: true, showUntracked: true },
};

// ═══════════════════════════════════════════════════════════════════════════
// Extension
// ═══════════════════════════════════════════════════════════════════════════

export default function grimoireFooter(pi: ExtensionAPI) {
  let enabled = true;
  let currentCtx: any = null;
  let footerDataRef: ReadonlyFooterDataProvider | null = null;
  let tuiRef: any = null;
  let getThinkingLevelFn: (() => string) | null = null;

  // ─── Status line rendering ─────────────────────────────────────────────

  /**
   * Render segments embedded into the top border of the input box.
   * Result: ╭─ seg1 │ seg2 │ seg3 ───────────────────────────╮
   */
  function renderTopBorder(ctx: SegmentContext, width: number): string {
    const sepChars = getSeparatorChars();
    const sepAnsi = getSepAnsi();
    const bc = (s: string) => `${sepAnsi}${s}${ansi.reset}`;
    const sep = sepChars.thinLeft;

    // Fixed chars: "╭─ " (3) + " ─...─╮" (at least 4 for trailing fill + cap)
    const overhead = 7;
    const parts: string[] = [];
    let contentWidth = 0;

    for (const segId of SEGMENTS_LEFT) {
      const rendered = renderSegment(segId, ctx);
      if (!rendered.visible || !rendered.content) continue;

      const segWidth = visibleWidth(rendered.content);
      const sepW = parts.length > 0 ? visibleWidth(sep) + 2 : 0; // " │ "

      if (contentWidth + segWidth + sepW + overhead > width) break;

      parts.push(rendered.content);
      contentWidth += segWidth + sepW;
    }

    if (parts.length === 0) {
      // No segments fit — just a plain rounded border
      return bc("╭") + bc("─".repeat(width - 2)) + bc("╮");
    }

    const segmentsStr = parts.join(` ${sepAnsi}${sep}${ansi.reset} `);
    const prefix = bc("╭─") + " " + segmentsStr + " ";
    const suffix = bc("╮");
    const usedWidth = visibleWidth(prefix) + visibleWidth(suffix);
    const fillLen = Math.max(1, width - usedWidth);
    return prefix + bc("─".repeat(fillLen)) + suffix;
  }

  // ─── Segment context builder ───────────────────────────────────────────

  function buildSegmentContext(theme: Theme): SegmentContext {
    const colors: ColorScheme = getDefaultColors();

    let input = 0, output = 0, cacheRead = 0, cacheWrite = 0, cost = 0;
    let lastAssistant: AssistantMessage | undefined;
    let thinkingLevelFromSession = "off";

    const sessionEvents = currentCtx?.sessionManager?.getBranch?.() ?? [];
    for (const e of sessionEvents) {
      if (e.type === "thinking_level_change" && e.thinkingLevel) {
        thinkingLevelFromSession = e.thinkingLevel;
      }
      if (e.type === "message" && e.message.role === "assistant") {
        const m = e.message as AssistantMessage;
        if (m.stopReason === "error" || m.stopReason === "aborted") continue;
        input += m.usage.input;
        output += m.usage.output;
        cacheRead += m.usage.cacheRead;
        cacheWrite += m.usage.cacheWrite;
        cost += m.usage.cost.total;
        lastAssistant = m;
      }
    }

    const contextTokens = lastAssistant
      ? lastAssistant.usage.input + lastAssistant.usage.output +
        lastAssistant.usage.cacheRead + lastAssistant.usage.cacheWrite
      : 0;
    const contextWindow = currentCtx?.model?.contextWindow || 0;
    const contextPercent = contextWindow > 0 ? (contextTokens / contextWindow) * 100 : 0;

    const gitBranch = footerDataRef?.getGitBranch() ?? null;
    const gitStatus = getGitStatus(gitBranch);

    const usingSubscription = currentCtx?.model
      ? currentCtx.modelRegistry?.isUsingOAuth?.(currentCtx.model) ?? false
      : false;

    return {
      model: currentCtx?.model,
      thinkingLevel: thinkingLevelFromSession || getThinkingLevelFn?.() || "off",
      usageStats: { input, output, cacheRead, cacheWrite, cost },
      contextPercent,
      contextWindow,
      autoCompactEnabled: currentCtx?.settingsManager?.getCompactionSettings?.()?.enabled ?? true,
      usingSubscription,
      git: gitStatus,
      options: SEGMENT_OPTIONS,
      theme,
      colors,
    };
  }

  // ─── Custom editor setup ───────────────────────────────────────────────

  function setupCustomEditor(ctx: any) {
    import("@mariozechner/pi-coding-agent").then(({ CustomEditor }) => {
      let currentEditor: any = null;
      let autocompleteFixed = false;

      const editorFactory = (tui: any, editorTheme: any, keybindings: any) => {
        const editor = new CustomEditor(tui, editorTheme, keybindings);
        currentEditor = editor;

        const originalHandleInput = editor.handleInput.bind(editor);
        editor.handleInput = (data: string) => {
          if (!autocompleteFixed && !(editor as any).autocompleteProvider) {
            autocompleteFixed = true;
            ctx.ui.setEditorComponent(editorFactory);
            currentEditor?.handleInput(data);
            return;
          }
          originalHandleInput(data);
        };

        const originalRender = editor.render.bind(editor);

        // Override render: segments in top border, input on bottom corners
        //  ╭─ ⚗ grimoire │ model │ path │ ⎇ branch ──────────╮
        //  │                                                   │  (if multiline)
        //  ╰ input text here                                   ╯
        editor.render = (width: number): string[] => {
          if (width < 10) return originalRender(width);

          const bc = (s: string) => `${getSepAnsi()}${s}${ansi.reset}`;
          // Content area: "╰ " prefix (2) + " ╯" suffix (2) = 4 overhead
          const contentWidth = Math.max(1, width - 4);
          const lines = originalRender(contentWidth);

          if (lines.length === 0 || !currentCtx) return lines;

          // Find bottom border from original render
          let bottomBorderIndex = lines.length - 1;
          for (let i = lines.length - 1; i >= 1; i--) {
            const stripped = lines[i]?.replace(/\x1b\[[0-9;]*m/g, "") || "";
            if (stripped.length > 0 && /^─{3,}/.test(stripped)) {
              bottomBorderIndex = i;
              break;
            }
          }

          const result: string[] = [];

          // Top border with embedded segments
          const segCtx = buildSegmentContext(ctx.ui.theme);
          result.push(renderTopBorder(segCtx, width));

          // Content lines count (between top and bottom borders)
          const contentLineCount = bottomBorderIndex - 1;

          if (contentLineCount <= 0) {
            // Empty editor — ╰ with empty space and ╯
            const pad = " ".repeat(contentWidth);
            result.push(`${bc("╰")} ${pad} ${bc("╯")}`);
          } else if (contentLineCount === 1) {
            // Single line — ╰ content ╯
            const lineContent = lines[1] || "";
            const lineVisWidth = visibleWidth(lineContent);
            const pad = " ".repeat(Math.max(0, contentWidth - lineVisWidth));
            result.push(`${bc("╰")} ${lineContent}${pad} ${bc("╯")}`);
          } else {
            // Multiple lines — │ for middle lines, ╰ on last
            for (let i = 1; i < bottomBorderIndex; i++) {
              const lineContent = lines[i] || "";
              const lineVisWidth = visibleWidth(lineContent);
              const pad = " ".repeat(Math.max(0, contentWidth - lineVisWidth));
              if (i < bottomBorderIndex - 1) {
                // Middle lines with side borders
                result.push(`${bc("│")} ${lineContent}${pad} ${bc("│")}`);
              } else {
                // Last content line gets ╰ ╯
                result.push(`${bc("╰")} ${lineContent}${pad} ${bc("╯")}`);
              }
            }
          }

          // Autocomplete lines (outside the box)
          for (let i = bottomBorderIndex + 1; i < lines.length; i++) {
            result.push(lines[i] || "");
          }

          return result;
        };

        return editor;
      };

      ctx.ui.setEditorComponent(editorFactory);

      // Footer — just for accessing footerData/tui refs (renders nothing)
      ctx.ui.setFooter((tui: any, _theme: Theme, footerData: ReadonlyFooterDataProvider) => {
        footerDataRef = footerData;
        tuiRef = tui;
        const unsub = footerData.onBranchChange(() => tui.requestRender());
        return {
          dispose: unsub,
          invalidate() {},
          render(): string[] { return []; },
        };
      });
    });
  }

  // ─── Event handlers ────────────────────────────────────────────────────

  pi.on("session_start", async (_event, ctx) => {
    currentCtx = ctx;
    if (typeof ctx.getThinkingLevel === "function") {
      getThinkingLevelFn = () => ctx.getThinkingLevel();
    }
    if (enabled && ctx.hasUI) setupCustomEditor(ctx);
  });

  // Set grimoire vibe when agent starts working
  pi.on("before_agent_start", async (_event, ctx) => {
    if (ctx.hasUI) ctx.ui.setWorkingMessage(getVibe());
  });

  // Refresh vibe on tool calls
  pi.on("tool_call", async (_event, ctx) => {
    if (ctx.hasUI) ctx.ui.setWorkingMessage(getVibe());
  });

  // Clear vibe when agent finishes
  pi.on("agent_end", async (_event, ctx) => {
    if (ctx.hasUI) ctx.ui.setWorkingMessage(undefined);
  });

  pi.on("tool_result", async (event, _ctx) => {
    if (event.toolName === "write" || event.toolName === "edit") {
      invalidateGitStatus();
    }
    if (event.toolName === "bash" && event.input?.command) {
      const cmd = String(event.input.command);
      if (/\bgit\s+(checkout|switch|branch\s+-[dDmM]|merge|rebase|pull|reset|worktree)/.test(cmd) ||
          /\bgit\s+stash\s+(pop|apply)/.test(cmd)) {
        invalidateGitStatus();
        invalidateGitBranch();
        setTimeout(() => tuiRef?.requestRender(), 100);
      }
    }
  });

  pi.on("user_bash", async (event, _ctx) => {
    if (/\bgit\s+(checkout|switch|merge|rebase|pull|reset)/.test(event.command)) {
      invalidateGitStatus();
      invalidateGitBranch();
      setTimeout(() => tuiRef?.requestRender(), 100);
      setTimeout(() => tuiRef?.requestRender(), 500);
    }
  });

  // ─── Commands ──────────────────────────────────────────────────────────

  pi.registerCommand("grimoire-footer", {
    description: "Toggle grimoire footer on/off",
    handler: async (_args, ctx) => {
      currentCtx = ctx;
      enabled = !enabled;
      if (enabled) {
        setupCustomEditor(ctx);
        ctx.ui.notify("Grimoire footer enabled", "info");
      } else {
        ctx.ui.setEditorComponent(undefined);
        ctx.ui.setFooter(undefined);
        footerDataRef = null;
        tuiRef = null;
        ctx.ui.notify("Defaults restored", "info");
      }
    },
  });
}
