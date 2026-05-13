import type { Theme, ThemeColor } from "@mariozechner/pi-coding-agent";
import type { ColorScheme, ColorValue, SemanticColor } from "./types.js";

// ANSI helpers
export const ansi = {
  getBgAnsi: (r: number, g: number, b: number) => `\x1b[48;2;${r};${g};${b}m`,
  getFgAnsi: (r: number, g: number, b: number) => `\x1b[38;2;${r};${g};${b}m`,
  getFgAnsi256: (code: number) => `\x1b[38;5;${code}m`,
  reset: "\x1b[0m",
};

function hexToRgb(hex: string): [number, number, number] {
  const h = hex.replace("#", "");
  return [
    parseInt(h.slice(0, 2), 16),
    parseInt(h.slice(2, 4), 16),
    parseInt(h.slice(4, 6), 16),
  ];
}

// Grimoire color scheme — dark purple/green security theme
const DEFAULT_COLORS: Required<ColorScheme> = {
  grimoire: "#b281d6",     // Purple (grimoire brand)
  model: "#d787af",        // Pink/mauve
  path: "#00afaf",         // Teal/cyan
  git: "success",
  gitDirty: "warning",
  gitClean: "success",
  thinking: "muted",
  context: "dim",
  contextWarn: "warning",
  contextError: "error",
  cost: "text",
  tokens: "muted",
  separator: "dim",
};

// Box/separator color — Catppuccin Mocha Mauve
const SEP_ANSI = ansi.getFgAnsi(203, 166, 247); // #cba6f7

function isHexColor(color: ColorValue): color is `#${string}` {
  return typeof color === "string" && color.startsWith("#");
}

function hexToAnsi(hex: string): string {
  const [r, g, b] = hexToRgb(hex);
  return `\x1b[38;2;${r};${g};${b}m`;
}

/** Resolve a semantic color to a concrete color value */
export function resolveColor(semantic: SemanticColor, presetColors?: ColorScheme): ColorValue {
  return presetColors?.[semantic] ?? DEFAULT_COLORS[semantic];
}

/** Apply a color value (hex or theme name) to text */
export function applyColor(theme: Theme, color: ColorValue, text: string): string {
  if (isHexColor(color)) {
    return `${hexToAnsi(color)}${text}${ansi.reset}`;
  }
  return theme.fg(color as ThemeColor, text);
}

/** Apply a semantic color to text */
export function fg(theme: Theme, semantic: SemanticColor, text: string, presetColors?: ColorScheme): string {
  const color = resolveColor(semantic, presetColors);
  return applyColor(theme, color, text);
}

/** Get the raw ANSI code for the separator color */
export function getSepAnsi(): string {
  return SEP_ANSI;
}

/** Get default color scheme */
export function getDefaultColors(): Required<ColorScheme> {
  return { ...DEFAULT_COLORS };
}
