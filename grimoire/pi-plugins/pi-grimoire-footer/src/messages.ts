// Grimoire working messages — mystical alternatives to "working..."

const GRIMOIRE_VIBES = [
  "summoning…",
  "divining…",
  "inscribing…",
  "archiving…",
  "casting…",
  "distilling…",
  "conjuring…",
  "scrying…",
  "transmuting…",
  "invoking…",
  "channeling…",
  "deciphering…",
  "brewing…",
  "binding…",
  "weaving…",
  "unearthing…",
  "attuning…",
  "forging…",
  "consecrating…",
  "unraveling…",
];

let lastIndex = -1;

/** Pick a random vibe, avoiding immediate repeats */
export function getVibe(): string {
  let index: number;
  do {
    index = Math.floor(Math.random() * GRIMOIRE_VIBES.length);
  } while (index === lastIndex && GRIMOIRE_VIBES.length > 1);
  lastIndex = index;
  return GRIMOIRE_VIBES[index];
}
