import { calculate, parseSet } from "./psi.mjs";

const byId = id => document.getElementById(id);
const form = byId("compareForm");
const alice = byId("alice");
const bob = byId("bob");
const results = byId("results");
const status = byId("status");
const runBtn = byId("runBtn");
let lastResult = null;

function countItems(input, display) {
  try {
    display.textContent = parseSet(input.value).length.toLocaleString() + " unique";
  } catch {
    display.textContent = "Too many / invalid";
  }
}
function refreshCounts() {
  countItems(alice, byId("aliceCount"));
  countItems(bob, byId("bobCount"));
}
function updateStatus(message, error = false) {
  status.textContent = message;
  status.classList.toggle("error", error);
}
function invalidateResults() {
  lastResult = null;
  results.hidden = true;
  refreshCounts();
}
function render(result) {
  byId("resultA").textContent = result.aliceSize.toLocaleString();
  byId("resultB").textContent = result.bobSize.toLocaleString();
  byId("resultCount").textContent = result.intersectionSize.toLocaleString();
  byId("overlap").textContent =
    result.aliceOverlapPercent + "% of Set A and " + result.bobOverlapPercent + "% of Set B overlap.";
  const panel = byId("matchPanel");
  panel.hidden = result.mode === "cardinality";
  const list = byId("matches");
  list.replaceChildren();
  if (!panel.hidden) {
    for (const item of result.intersection) {
      const li = document.createElement("li");
      li.textContent = item;
      list.append(li);
    }
    if (!result.intersection.length) {
      const li = document.createElement("li");
      li.textContent = "No shared items";
      list.append(li);
    }
  }
  byId("resultNotice").textContent = result.notice;
  results.hidden = false;
  lastResult = result;
}
for (const input of [alice, bob]) input.addEventListener("input", invalidateResults);
document.querySelectorAll('input[name="mode"]').forEach(radio =>
  radio.addEventListener("change", () => { lastResult = null; results.hidden = true; }));
byId("swapBtn").addEventListener("click", () => {
  [alice.value, bob.value] = [bob.value, alice.value];
  invalidateResults();
});
byId("clearBtn").addEventListener("click", () => {
  alice.value = "";
  bob.value = "";
  invalidateResults();
  updateStatus("Cleared. Enter items to compare.");
  alice.focus();
});
byId("exampleBtn").addEventListener("click", () => {
  alice.value = "record-001\nrecord-002\nrecord-003\nrecord-005";
  bob.value = "record-002\nrecord-003\nrecord-004\nrecord-006";
  invalidateResults();
  updateStatus("Example loaded.");
});
form.addEventListener("submit", async event => {
  event.preventDefault();
  const mode = form.elements.namedItem("mode").value;
  runBtn.disabled = true;
  updateStatus("Computing locally...");
  try {
    const result = await calculate(alice.value, bob.value, mode);
    render(result);
    updateStatus("Complete. No input was sent to a server.");
    results.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    invalidateResults();
    updateStatus(error instanceof Error ? error.message : "Comparison failed", true);
  } finally {
    runBtn.disabled = false;
  }
});
byId("downloadBtn").addEventListener("click", () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2) + "\n"], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "set-intersection-result.json";
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
refreshCounts();
