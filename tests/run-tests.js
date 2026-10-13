// Run with:  node tests/run-tests.js
// Checks every message in tests/testset.json against the engine and prints a summary.
// Exit code is 1 if any verdict differs from "expected", so you can use it as a quick check.

const path = require("path");
const fs = require("fs");
const { analyze } = require(path.join(__dirname, "..", "js", "engine.js"));

const verbose = process.argv.includes("-v");
const isUnseen = process.argv.includes("--unseen");
const isAll = process.argv.includes("--all");
const customFile = process.argv.find(a => a.endsWith(".json"));

let testFiles = [];
if (customFile) {
  testFiles = [path.resolve(customFile)];
} else if (isAll) {
  testFiles = [path.join(__dirname, "testset.json"), path.join(__dirname, "unseen-testset.json")];
} else if (isUnseen) {
  testFiles = [path.join(__dirname, "unseen-testset.json")];
} else {
  testFiles = [path.join(__dirname, "testset.json")];
}

let tests = [];
testFiles.forEach(f => {
  const data = JSON.parse(fs.readFileSync(f, "utf8"));
  tests = tests.concat(data);
});

let exact = 0;
const failures = [];
const catWarnings = [];
const stat = { scamMissedAsLow: 0, scamTotal: 0, genuineFlaggedScam: 0, genuineFlagged: 0, genuineTotal: 0 };

for (const t of tests) {
  const r = analyze(t.text);
  const ok = r.verdict === t.expected;
  if (ok) exact++; else failures.push({ t, r });

  if (t.expected === "scam") {
    stat.scamTotal++;
    if (r.verdict === "low_risk") stat.scamMissedAsLow++;
  }
  if (t.expected === "low_risk") {
    stat.genuineTotal++;
    if (r.verdict !== "low_risk") stat.genuineFlagged++;
    if (r.verdict === "scam") stat.genuineFlaggedScam++;
  }
  if (ok && t.category && r.verdict !== "low_risk") {
    const want = [].concat(t.category);
    if (!want.includes(r.category)) catWarnings.push(`${t.id}: expected category ${want.join("/")}, got ${r.category}`);
  }
  if (verbose || !ok) {
    console.log(`${ok ? "PASS" : "FAIL"} ${t.id} [${t.lang}] expected=${t.expected} got=${r.verdict} score=${r.score} category=${r.category}`);
    if (!ok) {
      console.log("     text: " + t.text);
      console.log("     debug: " + JSON.stringify({
        categories: Object.fromEntries(Object.entries(r.debug.categories).map(([k, v]) => [k, v.score])),
        signals: r.debug.signals.map((s) => `${s.id}:${s.points}`)
      }));
    }
  }
}

console.log("\n=== Summary ===");
console.log(`Exact verdict match:            ${exact}/${tests.length}`);
console.log(`Scams called low_risk (worst):  ${stat.scamMissedAsLow}/${stat.scamTotal}`);
console.log(`Genuine flagged at all:         ${stat.genuineFlagged}/${stat.genuineTotal}`);
console.log(`Genuine flagged as scam:        ${stat.genuineFlaggedScam}/${stat.genuineTotal}`);
if (catWarnings.length) {
  console.log("\nCategory differences (verdict was right):");
  catWarnings.forEach((w) => console.log("  - " + w));
}
process.exit(failures.length ? 1 : 0);
