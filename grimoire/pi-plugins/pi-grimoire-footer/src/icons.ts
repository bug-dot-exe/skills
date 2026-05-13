export interface IconSet {
  grimoire: string;
  model: string;
  folder: string;
  branch: string;
  branchDirty: string;
  context: string;
  cost: string;
  cache: string;
  input: string;
  auto: string;
}

export const SEP_DOT = " · ";

// Thinking level icons — eye opening progression
export interface ThinkingIcons {
  minimal: string;
  low: string;
  medium: string;
  high: string;
  xhigh: string;
}

const NERD_THINKING: ThinkingIcons = {
  minimal: "󰈈",       // nf-md-eye_off — closed
  low: "󰋑",           // nf-md-eye_outline — barely open
  medium: "󰊠",        // nf-md-ghost — seeing
  high: "󰛂",          // nf-md-eye_check — wide open
  xhigh: "󱟱",         // nf-md-eye_arrow_right — all-seeing
};

const ASCII_THINKING: ThinkingIcons = {
  minimal: "○",
  low: "◔",
  medium: "◑",
  high: "◕",
  xhigh: "◉",
};

// Nerd Font icons — alchemy/magic theme
const NERD_ICONS: IconSet = {
  grimoire: "\u{F00BD}",  // nf-md-book_open — grimoire
  model: "✧",           // sparkle
  folder: "󰉋",          // nf-md-folder
  branch: "󰘬",          // nf-md-source_branch — clean
  branchDirty: "󰊢",     // nf-md-git — dirty/volatile
  context: "󱩃",         // nf-md-flask_round_bottom — flask filling up
  cost: "󰖺",            // nf-md-scale_balance — scales
  cache: "󱋊",           // nf-md-scroll — stored knowledge
  input: "󰁍",           // nf-md-arrow_down
  auto: "\u{F0068}",    // nf-md-lightning_bolt
};

// ASCII/Unicode fallback icons
const ASCII_ICONS: IconSet = {
  grimoire: "⚗",
  model: "✧",
  folder: "~",
  branch: "⎇",
  branchDirty: "⎇",
  context: "◫",
  cost: "⚖",
  cache: "§",
  input: "in:",
  auto: "⚡",
};

// Separator characters
export interface SeparatorChars {
  thinLeft: string;
  thinRight: string;
}

const NERD_SEPS: SeparatorChars = {
  thinLeft: "\uE0B1",   //
  thinRight: "\uE0B3",  //
};

const ASCII_SEPS: SeparatorChars = {
  thinLeft: "|",
  thinRight: "|",
};

export function getIcons(): IconSet {
  return NERD_ICONS;
}

export function getThinkingIcon(level: string): string | undefined {
  return (NERD_THINKING as Record<string, string>)[level];
}

export function getSeparatorChars(): SeparatorChars {
  return NERD_SEPS;
}
