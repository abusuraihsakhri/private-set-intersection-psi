/* Local educational set comparison. This is NOT cryptographically private two-party PSI. */
export const MAX_ITEMS = 2000;
export const MAX_ITEM_LENGTH = 512;

export function parseSet(text) {
  if (typeof text !== "string") throw new TypeError("Set input must be text");
  const unique = new Set();
  for (const raw of text.split(/\r?\n/)) {
    const item = raw.trim();
    if (!item) continue;
    if (item.length > MAX_ITEM_LENGTH) throw new Error("An item exceeds 512 characters");
    unique.add(item);
    if (unique.size > MAX_ITEMS) throw new Error("Maximum 2,000 unique items per set");
  }
  return [...unique];
}

async function sha256(value, cryptoAPI) {
  if (!cryptoAPI?.subtle) {
    throw new Error("SHA-256 requires a secure browser context (HTTPS or localhost)");
  }
  const bytes = new TextEncoder().encode(value);
  const digest = await cryptoAPI.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

export async function calculate(aliceText, bobText, mode = "intersection", cryptoAPI = globalThis.crypto) {
  if (!["intersection", "cardinality", "hash"].includes(mode)) throw new Error("Unknown comparison mode");
  const alice = parseSet(aliceText);
  const bob = parseSet(bobText);
  if (!alice.length || !bob.length) throw new Error("Enter at least one item in each set");
  let matches;
  if (mode === "hash") {
    // Shared, unsalted public hashes do not provide PSI privacy.
    const [aliceHashes, bobHashes] = await Promise.all([
      Promise.all(alice.map(item => sha256(item, cryptoAPI))),
      Promise.all(bob.map(item => sha256(item, cryptoAPI))),
    ]);
    const rightHashes = new Set(bobHashes);
    matches = alice.filter((_, index) => rightHashes.has(aliceHashes[index]));
  } else {
    const right = new Set(bob);
    matches = alice.filter(item => right.has(item));
  }
  const count = matches.length;
  return {
    mode,
    aliceSize: alice.length,
    bobSize: bob.length,
    intersectionSize: count,
    aliceOverlapPercent: Math.round(1000 * count / alice.length) / 10,
    bobOverlapPercent: Math.round(1000 * count / bob.length) / 10,
    ...(mode !== "cardinality" ? { intersection: matches } : {}),
    notice: "Local educational comparison only; not a distributed or cryptographically private PSI protocol.",
  };
}
