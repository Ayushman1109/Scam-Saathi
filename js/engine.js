/*  engine.js — rule-based scam checker. No AI, no network, no API keys.
 *  Works in the browser (after rules.js) and in Node (for the tests).
 *
 *    const result = ScamSaathi.analyze("aapka SIM block ho jayega ...");
 *    result.verdict   // "scam" | "suspicious" | "low_risk" | "empty"
 *
 *  Pipeline: normalise -> tokenise -> blank out "safe" phrases -> match scam phrases
 *            (fuzzy) -> add link/APK/urgency signals -> total score -> verdict.
 */
(function (root) {
  "use strict";

  var RULES = (typeof module !== "undefined" && module.exports) ? require("./rules.js") : root.SCAM_RULES;
  var MAX_GAP = 5;       // words allowed between the words of a phrase (scam phrases)
  var SAFE_GAP = 1;      // safe phrases must be (almost) adjacent
  var LEVELS = ["strong", "medium", "weak"];

  // ---------- 1. normalise + tokenise ----------
  function normalize(s) {
    s = String(s || "").normalize("NFC").toLowerCase();
    s = s.replace(/[​-‍﻿]/g, "");                       // zero-width characters
    s = s.replace(/़/g, "");                                      // Devanagari nukta
    s = s.replace(/ँ/g, "ं");                                // chandrabindu -> anusvara
    s = s.replace(/[०-९]/g, function (d) { return String(d.charCodeAt(0) - 0x0966); });
    s = s.replace(/(?<=\d),(?=\d)/g, "");                         // 10,000 -> 10000
    s = s.replace(/['’`]/g, "");                                  // don't -> dont
    s = s.replace(/\b(?:[a-z]\.){2,}[a-z]?\b/g, function (m) { return m.replace(/\./g, ""); }); // o.t.p -> otp
    s = s.replace(/\b([a-z0-9])[.\-_/]([a-z0-9])[.\-_/]([a-z0-9])\b/gi, "$1$2$3"); // o-t-p, k-y-c -> otp, kyc
    s = s.replace(/([a-zऀ-ॿ])\1{2,}/g, "$1$1");              // bhejooo -> bhejoo
    // Anti-evasion leetspeak deobfuscation for common scam keywords
    s = s.replace(/\b[0o]tp\b/gi, "otp")
         .replace(/\bp[1i]n\b/gi, "pin")
         .replace(/\bs[1i]m\b/gi, "sim")
         .replace(/\bk[y¥]c\b/gi, "kyc")
         .replace(/\bc[1il]{1,2}ck\b/gi, "click")
         .replace(/\bl[1i]nk\b/gi, "link")
         .replace(/\bbl[0o]ck\b/gi, "block")
         .replace(/\bd[0o]wnl[0o]ad\b/gi, "download");
    return s;
  }

  function tokenize(s) {
    return normalize(s).split(/[^\p{L}\p{M}\p{N}]+/u).filter(Boolean);
  }

  var phraseCache = {};
  function phraseTokens(p) {
    return phraseCache[p] || (phraseCache[p] = tokenize(p));
  }

  // ---------- 2. fuzzy matching ----------
  function levenshtein(a, b) {
    var prev = [], j, i;
    for (j = 0; j <= b.length; j++) prev[j] = j;
    for (i = 1; i <= a.length; i++) {
      var cur = [i];
      for (j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[b.length];
  }

  // a = word in the message, b = word in the phrase. Fuzzy only for words of 5+ letters.
  function tokenMatch(a, b, fuzzy) {
    if (a === b) return true;
    if (!fuzzy || /^\d+$/.test(b)) return false;
    var lim = b.length <= 4 ? 0 : (b.length <= 7 ? 1 : 2);
    if (lim === 0 || Math.abs(a.length - b.length) > lim) return false;
    return levenshtein(a, b) <= lim;
  }

  // Find the phrase's words in order, allowing up to `gap` other words between them.
  function findPhrase(tokens, ptoks, fuzzy, gap) {
    for (var s = 0; s < tokens.length; s++) {
      if (!tokenMatch(tokens[s], ptoks[0], fuzzy)) continue;
      var pos = s, ok = true;
      for (var k = 1; k < ptoks.length; k++) {
        var found = -1;
        for (var j = pos + 1; j <= pos + 1 + gap && j < tokens.length; j++) {
          if (tokenMatch(tokens[j], ptoks[k], fuzzy)) { found = j; break; }
        }
        if (found < 0) { ok = false; break; }
        pos = found;
      }
      if (ok) return { start: s, end: pos };
    }
    return null;
  }

  // Blank out "never share your OTP"-type phrases so they cannot trigger scam phrases.
  function maskSafe(tokens) {
    var t = tokens.slice();
    var sorted = RULES.safePhrases.slice().sort(function (a, b) {
      return phraseTokens(b).length - phraseTokens(a).length;
    });
    sorted.forEach(function (p) {
      var ptoks = phraseTokens(p), m;
      while ((m = findPhrase(t, ptoks, false, SAFE_GAP))) {
        for (var i = m.start; i <= m.end; i++) t[i] = "_";
      }
    });
    return t;
  }

  // ---------- 3. links, APKs, phone numbers ----------
  var URL_RE = /\b(?:https?:\/\/)?(?:[a-z0-9-]+\.)+(?:com|in|xyz|top|club|online|site|link|info|co|app|live|vip|shop|net|org|me|cc|ly|gl|io|biz|pw|tk|ml|ga|cf|gq|sbi|gov|ink|click|work|fun|icu|buzz|cyou)\b(?:[\/?#][^\s]*)?/g;
  var PHONE_RE = /(?:^|[^\d])(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)/;

  function hostOf(url) {
    return url.replace(/^https?:\/\//, "").split(/[\/?#:]/)[0].replace(/^www\./, "");
  }
  function domainIn(host, list) {
    return list.some(function (d) { return host === d || host.slice(-(d.length + 1)) === "." + d; });
  }

  function linkSignals(raw) {
    var G = RULES.generic, P = G.points, lower = raw.toLowerCase(), best = null, m;
    URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(lower))) {
      if (lower[m.index - 1] === "@") continue;                         // e-mail address
      var host = hostOf(m[0]), sig = null;
      if (domainIn(host, G.trustedDomains)) continue;
      if (domainIn(host, G.shorteners)) sig = { id: "shortener", points: P.link + P.shortener };
      else if (G.brandWords.some(function (w) { return host.indexOf(w) !== -1; })) sig = { id: "lookalike", points: P.link + P.lookalike };
      else sig = { id: "link", points: P.link };
      if (!best || sig.points > best.points) best = sig;
    }
    return best;
  }

  // ---------- 4. analyse ----------
  function anyPhrase(tokens, list) {
    return list.some(function (p) { return findPhrase(tokens, phraseTokens(p), true, MAX_GAP); });
  }

  function analyze(text) {
    var raw = String(text == null ? "" : text);
    if (!raw.trim()) {
      return {
        verdict: "empty",
        score: 0,
        headlineHi: "कृपया जाँचने के लिए मैसेज लिखें या बोलें।",
        headlineEn: "Please enter or paste a message to analyze.",
        stepsHi: [],
        stepsEn: [],
        reasonsHi: [],
        reasonsEn: []
      };
    }
    var tokens = maskSafe(tokenize(raw));
    var W = RULES.weights, T = RULES.thresholds, G = RULES.generic;

    // (a) scam-type phrases
    var cats = {};
    Object.keys(RULES.categories).forEach(function (id) {
      var cat = RULES.categories[id], spans = [], hits = [];
      LEVELS.forEach(function (level) {
        (cat[level] || []).forEach(function (p) {
          var m = findPhrase(tokens, phraseTokens(p), true, MAX_GAP);
          if (!m) return;
          var overlap = spans.some(function (s) { return m.start <= s.end && s.start <= m.end; });
          if (overlap) return;                                         // same words already counted
          spans.push(m);
          hits.push({ phrase: p, level: level, points: W[level] });
        });
      });
      if (hits.length) {
        // strongest hit counts fully; each extra distinct hit adds 0.5 (max +2)
        cats[id] = { score: hits[0].points + Math.min(2, 0.5 * (hits.length - 1)), hits: hits };
      }
    });

    // (b) generic signals
    var signals = [];
    var link = linkSignals(raw);
    if (link) signals.push(link);
    if (/\.apk\b|\bapk\b/i.test(raw)) signals.push({ id: "apk", points: G.points.apk });
    if (PHONE_RE.test(raw)) signals.push({ id: "phone", points: G.points.phone });
    if (anyPhrase(tokens, G.urgency)) signals.push({ id: "urgency", points: G.points.urgency });
    if (anyPhrase(tokens, G.action)) signals.push({ id: "action", points: G.points.action });

    // (c) total + verdict
    var total = 0, topId = null, topScore = 0;
    Object.keys(cats).forEach(function (id) {
      total += cats[id].score;
      if (cats[id].score > topScore) { topScore = cats[id].score; topId = id; }
    });
    signals.forEach(function (s) { total += s.points; });

    var verdict = total >= T.scam ? "scam" : (total >= T.suspicious ? "suspicious" : "low_risk");
    var V = RULES.verdicts[verdict];

    var result = {
      verdict: verdict,
      colour: V.colour,
      score: Math.round(total * 10) / 10,
      category: null,
      categoryNameHi: null,
      categoryNameEn: null,
      headlineHi: V.headlineHi,
      headlineEn: V.headlineEn,
      explanationHi: "",
      explanationEn: "",
      stepsHi: [],
      stepsEn: [],
      reasonsHi: [],
      reasonsEn: [],
      helplinesHi: "",
      helplinesEn: "",
      spokenHi: "",
      spokenEn: "",
      debug: { categories: cats, signals: signals }
    };

    if (verdict === "low_risk") {
      result.explanationHi = V.noteHi;
      result.explanationEn = V.noteEn;
      result.stepsHi = V.stepsHi.slice();
      result.stepsEn = V.stepsEn.slice();
    } else {
      var info = topId ? RULES.categories[topId] : RULES.genericRisk;
      result.category = topId || "generic_risk";
      result.categoryNameHi = info.nameHi;
      result.categoryNameEn = info.nameEn;
      result.explanationHi = info.explainHi;
      result.explanationEn = info.explainEn;
      result.stepsHi = info.stepsHi.slice();
      result.stepsEn = info.stepsEn.slice();
      result.helplinesHi = RULES.helplinesHi;
      result.helplinesEn = RULES.helplinesEn;
      Object.keys(cats).forEach(function (id) {
        if (cats[id].score >= W.medium) {
          result.reasonsHi.push(RULES.categories[id].reasonHi);
          result.reasonsEn.push(RULES.categories[id].reasonEn);
        }
      });
      signals.forEach(function (s) {
        result.reasonsHi.push(G.labelsHi[s.id]);
        result.reasonsEn.push(G.labelsEn[s.id]);
      });
    }
    result.spokenHi = [result.headlineHi, result.explanationHi].concat(result.stepsHi.slice(0, 2)).join(" ");
    result.spokenEn = [result.headlineEn, result.explanationEn].concat(result.stepsEn.slice(0, 2)).join(" ");
    return result;
  }

  var api = { analyze: analyze, normalize: normalize, tokenize: tokenize };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.ScamSaathi = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
