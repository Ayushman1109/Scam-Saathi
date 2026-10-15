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
    s = s.replace(/[०-९]/g, function (d) { return String(d.charCodeAt(0) - 0x0966); }); // Devanagari numerals
    s = s.replace(/[০-৯]/g, function (d) { return String(d.charCodeAt(0) - 0x09E6); }); // Bengali numerals
    s = s.replace(/(?<=\d),(?=\d)/g, "");                         // 10,000 -> 10000
    s = s.replace(/['’`]/g, "");                                  // don't -> dont
    s = s.replace(/\b(?:[a-z]\.){2,}[a-z]?\b/g, function (m) { return m.replace(/\./g, ""); }); // o.t.p -> otp
    s = s.replace(/\b([a-z0-9])[.\-_/]([a-z0-9])[.\-_/]([a-z0-9])\b/gi, "$1$2$3"); // o-t-p, k-y-c -> otp, kyc
    s = s.replace(/([a-zऀ-ॿ০-৯])/g, "$1");
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

  // ---------- 4. warning signs and evidence extraction ----------
  function extractWarningSigns(raw, tokens, cats, signals, G, W, verdict) {
    if (verdict === "low_risk") {
      return [];
    }
    var clues = [];
    var norm = raw.toLowerCase();

    // Clue 1: Urgency or threats of account closure / disconnection / arrest
    var hasUrgencySignal = signals.some(function (s) { return s.id === "urgency"; });
    var threatCats = ["sim_kyc", "bank_threat", "electricity", "authority_threat"];
    var hasThreatCat = threatCats.some(function (c) { return cats[c] && cats[c].score >= W.medium; });
    if (hasUrgencySignal || hasThreatCat) {
      var evidenceQuotes = [];
      threatCats.forEach(function (c) {
        if (cats[c] && cats[c].hits) {
          cats[c].hits.forEach(function (h) {
            if (h.level === "strong" || h.level === "medium") evidenceQuotes.push(h.phrase);
          });
        }
      });
      G.urgency.forEach(function (w) {
        if (evidenceQuotes.length < 3 && norm.indexOf(w.toLowerCase()) !== -1) {
          evidenceQuotes.push(w);
        }
      });
      var quoteStr = evidenceQuotes.slice(0, 2).map(function (q) { return '“' + q + '”'; }).join(", ");
      clues.push({
        id: "urgency_threat",
        labelEn: "Creates artificial urgency or threatens account closure / service cut / legal action",
        labelHi: "जल्दबाज़ी बनाता है या खाता/बिजली/सिम बंद होने या कानूनी कार्रवाई का डर दिखाता है",
        labelBn: "তাড়াহুড়ো সৃষ্টি করে বা অ্যাকাউন্ট/বিদ্যুৎ/সিম বন্ধ বা আইনি ব্যবস্থার ভয় দেখায়",
        evidence: quoteStr || "Artificial urgency / threat detected in message"
      });
    }

    // Clue 2: Requests an OTP, PIN, password, or payment
    var credCats = ["otp_request", "info_request", "upi_refund", "ponzi_investment"];
    var hasCredCat = credCats.some(function (c) { return cats[c] && cats[c].score >= W.medium; });
    var credMatch = raw.match(/\b(?:otp|upi\s*pin|atm\s*pin|cvv|password|ओटीपी|पिन|পাসওয়ার্ড|ওটিপি)\b/i);
    if (hasCredCat || credMatch) {
      var evidenceCred = [];
      credCats.forEach(function (c) {
        if (cats[c] && cats[c].hits) {
          cats[c].hits.forEach(function (h) {
            if (h.level === "strong" || h.level === "medium") evidenceCred.push(h.phrase);
          });
        }
      });
      if (credMatch && evidenceCred.indexOf(credMatch[0]) === -1) {
        evidenceCred.push(credMatch[0]);
      }
      var quoteStr2 = evidenceCred.slice(0, 2).map(function (q) { return '“' + q + '”'; }).join(", ");
      clues.push({
        id: "credential_payment",
        labelEn: "Requests confidential OTP, PIN, password, or payment / money transfer",
        labelHi: "गोपनीय ओटीपी, यूपीआई पिन, पासवर्ड या पैसे ट्रांसफर करने की मांग करता है",
        labelBn: "গোপনীয় ওটিপি, ইউপিআই পিন, পাসওয়ার্ড বা টাকা ট্রান্সফারের দাবি করে",
        evidence: quoteStr2 || "Confidential credential / money request detected"
      });
    }

    // Clue 3: Uses an unfamiliar link or unexpected reward
    var hasLinkSignal = signals.some(function (s) { return s.id === "link" || s.id === "shortener" || s.id === "lookalike"; });
    var rewardCats = ["lottery", "govt_scheme", "ponzi_investment"];
    var hasRewardCat = rewardCats.some(function (c) { return cats[c] && cats[c].score >= W.medium; });
    if (hasLinkSignal || hasRewardCat) {
      var evidenceLink = [];
      URL_RE.lastIndex = 0;
      var urls = raw.match(URL_RE);
      if (urls && urls.length) {
        urls.forEach(function (u) { evidenceLink.push(u); });
      }
      rewardCats.forEach(function (c) {
        if (cats[c] && cats[c].hits) {
          cats[c].hits.forEach(function (h) {
            if (h.level === "strong" || h.level === "medium") evidenceLink.push(h.phrase);
          });
        }
      });
      var quoteStr3 = evidenceLink.slice(0, 2).map(function (q) { return '“' + q + '”'; }).join(", ");
      clues.push({
        id: "unfamiliar_link_reward",
        labelEn: "Uses an unfamiliar web link or offers an unexpected reward / prize",
        labelHi: "अपरिचित वेब लिंक का उपयोग करता है या अनपेक्षित लॉटरी/इनाम का लालच देता है",
        labelBn: "অপরিচিত ওয়েব লিঙ্ক ব্যবহার করে বা অপ্রত্যাশিত পুরস্কার/লটারির প্রলোভন দেয়",
        evidence: quoteStr3 || "Unverified link or prize incentive detected"
      });
    }

    // Clue 4: Asks recipient to install an app or take an unusual action
    var hasApkSignal = signals.some(function (s) { return s.id === "apk"; });
    var hasPhoneSignal = signals.some(function (s) { return s.id === "phone"; });
    var hasActionSignal = signals.some(function (s) { return s.id === "action"; });
    if (hasApkSignal || hasPhoneSignal || hasActionSignal) {
      var evidenceAction = [];
      var apkMatch = raw.match(/\b[\w.-]+\.apk\b|\bapk\b/i);
      if (apkMatch) evidenceAction.push(apkMatch[0]);
      var phoneMatch = raw.match(PHONE_RE);
      if (phoneMatch) evidenceAction.push(phoneMatch[0].trim());
      G.action.forEach(function (a) {
        if (evidenceAction.length < 2 && norm.indexOf(a.toLowerCase()) !== -1) {
          evidenceAction.push(a);
        }
      });
      var quoteStr4 = evidenceAction.slice(0, 2).map(function (q) { return '“' + q + '”'; }).join(", ");
      clues.push({
        id: "app_or_unusual_action",
        labelEn: "Asks to install an app (.apk) or take an unusual action (call personal number / WhatsApp)",
        labelHi: "ऐप (.apk) इंस्टॉल करने या असामान्य कदम उठाने (निजी नंबर/व्हाट्सएप पर संपर्क) को कहता है",
        labelBn: "অ্যাপ (.apk) ইনস্টল করতে বা অস্বাভাবিক পদক্ষেপ নিতে (ব্যক্তিগত নম্বর/হোয়াটসঅ্যাপে যোগাযোগ) বলে",
        evidence: quoteStr4 || "Prompt to install app or contact unverified number detected"
      });
    }

    return clues;
  }

  // ---------- 5. analyse ----------
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
        headlineBn: "যাচাই করার জন্য দয়া করে একটি মেসেজ লিখুন বা পেস্ট করুন।",
        stepsHi: [],
        stepsEn: [],
        stepsBn: [],
        reasonsHi: [],
        reasonsEn: [],
        reasonsBn: [],
        warningSigns: [],
        hasEvidence: false,
        evidenceNoteEn: "",
        evidenceNoteHi: "",
        evidenceNoteBn: "",
        avoidEn: "", avoidHi: "", avoidBn: "",
        verifyEn: "", verifyHi: "", verifyBn: "",
        reportEn: "", reportHi: "", reportBn: "",
        nextSteps: {
          avoidEn: "", avoidHi: "", avoidBn: "",
          verifyEn: "", verifyHi: "", verifyBn: "",
          reportEn: "", reportHi: "", reportBn: ""
        }
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

    // (a.2) Layer 1: Structural Intent & Multiplier Abstraction
    // Detects structural multiplier scams, arbitrage promises, and Action+Multiplier intent pairing
    var MULTIPLIER_ASSET_RE = /\b(?:\d+\s*x|double|triple|quadruple|multiply|grow)\s+(?:my|your|his|her|their|our|the|this)?\s*(?:money|cash|deposit|investment|funds|amount|savings|rupees|rs|paisa|paise)\b/i;
    var MULTIPLIER_ASSET_HI = /(?:^|[^\p{L}\p{N}])(?:\d+|२|३|५|१०)?\s*(?:गुना|x|डबल|ट्रिपल|दोगुना|तिगुना)\s*(?:पैसा|पैसे|रुपये|रुपए|रकम|डिपॉजिट|इन्वेस्टमेंट)(?=$|[^\p{L}\p{N}])/u;
    var MULTIPLIER_ASSET_BN = /(?:^|[^\p{L}\p{N}])(?:\d+|২|৩|৫|১০)?\s*(?:গুণ|x|ডাবল|ট্রিপল|দ্বিগুণ|তিনগুণ)\s*(?:টাকা|পয়সা|অর্থ|আমানত|বিনিয়োগ)(?=$|[^\p{L}\p{N}])/u;

    var ARBITRAGE_RE = /\b(?:turn|convert|grow|change|invest|give|send|pay)\s+(?:(?:rs\.?|inr|₹)\s*)?\d+[kK]?\s*(?:into|to\s+get|and\s+get|for|to\s+turn\s+into)\s+(?:(?:rs\.?|inr|₹)\s*)?\d+[kK]?\b/i;

    var SLOT_A_RE = /\b(?:(?:give|send|transfer|pay|invest|deposit|put)(?:\s+(?:him|her|them|me|us))?(?:\s+(?:some|\d+|any))?\s*(?:money|cash|funds|amount|savings|deposit|rupees|rs\.?|inr|₹)|send\s+(?:on\s+)?qr|pay\s+(?:on\s+)?qr|scan\s+qr|send\s+(?:on\s+)?upi|pay\s+(?:on\s+)?upi|transfer\s+(?:on\s+)?upi|qr\s+(?:code\s+)?to\s+pay|paise?\s+(?:do|de|dena|bhejo?|bhej|transfer|lagao)|rupaye?\s+(?:do|de|bhejo?)|qr\s+(?:par|pe)\s+bhejo?|upi\s+(?:par|pe)\s+bhejo?)\b/i;
    var SLOT_A_UNICODE = /(?:^|[^\p{L}\p{N}])(?:पैसे?\s+(?:दो|दें|भेजो?|भेजें|लगाओ|डालो)|रुपये?\s+(?:दो|भेजो?)|টাকা\s*(?:দিন|পাঠান|ট্রান্সফার|দিন\s*না)|পয়সা\s*দিন)(?=$|[^\p{L}\p{N}])/u;

    var SLOT_B_RE = /\b(?:\d+\s*x\b|double|triple|quadruple|multiply|multiplying|doubling|tripling|dugna|doguna|tinguna|teenguna|guaranteed\s+(?:returns?|profits?)|daily\s+profit|quick\s+profit|make\s+(?:you\s+)?rich|grow\s+(?:your\s+)?money|get\s+rich)\b/i;
    var SLOT_B_UNICODE = /(?:^|[^\p{L}\p{N}])(?:\d+\s*गुना|\d+\s*গুণ|डबल|ट्रिपल|दोगुना|तिगुना|तीन\s*गुना|ডাবল|ট্রিপল|দ্বিগুণ|তিনগুণ|নিশ্চিত\s*লাভ|मुनाफा)(?=$|[^\p{L}\p{N}])/u;

    var structuralHit = null;
    var m1 = raw.match(MULTIPLIER_ASSET_RE) || raw.match(MULTIPLIER_ASSET_HI) || raw.match(MULTIPLIER_ASSET_BN);
    if (m1) {
      structuralHit = m1[0].trim();
    } else {
      var m2 = raw.match(ARBITRAGE_RE);
      if (m2) {
        structuralHit = m2[0].trim();
      } else {
        var matchA = raw.match(SLOT_A_RE) || raw.match(SLOT_A_UNICODE);
        var matchB = raw.match(SLOT_B_RE) || raw.match(SLOT_B_UNICODE);
        if (matchA && matchB) {
          structuralHit = matchA[0].trim() + " ... " + matchB[0].trim();
        }
      }
    }

    if (structuralHit) {
      if (!cats.ponzi_investment) {
        cats.ponzi_investment = {
          score: W.strong,
          hits: [{ phrase: structuralHit, level: "strong", points: W.strong }]
        };
      } else {
        cats.ponzi_investment.hits.push({ phrase: structuralHit, level: "strong", points: W.strong });
        cats.ponzi_investment.score = Math.max(cats.ponzi_investment.score, W.strong);
      }
    }

    // (a.3) Generic Viral Giveaway & Fake Reward Phishing Detection
    // Catches "Google Pay 9th Anniversary Gift ₹6,000", "Amazon Free Gift Claim here", etc.
    var REWARD_REGEX = /\b(?:(?:anniversary|jubilee|celebration|birthday|festival|diwali|puja|pooja|new\s*year|eid|christmas|special)\s+(?:gift|reward|bonus|prize|cash|offer)|(?:claim|collect|get)\s+(?:here|now|your\s+gift|your\s+reward|your\s+prize|it\s+here|it\s+now|yours\s+now)|i\s+(?:just\s+)?(?:got|received)\s+(?:₹|rs\.?|inr)?\s*\d+|(?:gift|reward|prize|cashback|bonus|voucher)\s*(?:of\s*)?(?:₹|rs\.?|inr)?\s*\d+|free\s+(?:recharge|gift|smartphone|laptop|iphone)|selected\s+for\s+(?:free\s+)?(?:gift|reward|prize))\b/i;
    var REWARD_UNICODE = /(?:^|[^\p{L}\p{N}])(?:(?:दीवाली|त्योहार|पूजा|वार्षिकोत्सव|ईद)\s*(?:उपहार|गिफ्ट|ऑफर)|(?:পূজা|উৎসব|ঈদ|বার্ষিকী)\s*(?:অফার|উপহার|পুরস্কার)|(?:गिफ्ट|इनाम|उपहार|रुपये|রিচার্জ|পুরস্কার|উপহার)\s*(?:पाएं|मिलें|क्लेम|দাবি\s*করুন|সংগ্রহ\s*করুন|পান)|ফ্রি\s*রিচার্জ|বিনামূল্যে\s*(?:উপহার|স্মার্টফোন))(?=$|[^\p{L}\p{N}])/u;

    var rewardMatch = raw.match(REWARD_REGEX) || raw.match(REWARD_UNICODE);
    var hasUntrustedLink = linkSignals(raw) !== null;
    if (rewardMatch && (hasUntrustedLink || anyPhrase(tokens, G.action))) {
      var rSnippet = rewardMatch[0].trim();
      if (!cats.lottery) {
        cats.lottery = {
          score: W.strong,
          hits: [{ phrase: rSnippet, level: "strong", points: W.strong }]
        };
      } else {
        cats.lottery.hits.push({ phrase: rSnippet, level: "strong", points: W.strong });
        cats.lottery.score = Math.max(cats.lottery.score, W.strong);
      }
    }

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
    var info = verdict === "low_risk" ? null : (topId ? RULES.categories[topId] : RULES.genericRisk);

    // (d) warning signs with concrete evidence
    var warningSigns = extractWarningSigns(raw, tokens, cats, signals, G, W, verdict);
    var hasEvidence = warningSigns.length > 0;

    var result = {
      verdict: verdict,
      colour: V.colour,
      score: Math.round(total * 10) / 10,
      category: topId || (verdict !== "low_risk" ? "generic_risk" : null),
      categoryNameHi: info ? info.nameHi : null,
      categoryNameEn: info ? info.nameEn : null,
      categoryNameBn: info ? (info.nameBn || info.nameEn) : null,
      headlineHi: V.headlineHi,
      headlineEn: V.headlineEn,
      headlineBn: V.headlineBn || V.headlineEn,
      explanationHi: "",
      explanationEn: "",
      explanationBn: "",
      stepsHi: [],
      stepsEn: [],
      stepsBn: [],
      reasonsHi: [],
      reasonsEn: [],
      reasonsBn: [],
      helplinesHi: RULES.helplinesHi,
      helplinesEn: RULES.helplinesEn,
      helplinesBn: RULES.helplinesBn || RULES.helplinesEn,
      warningSigns: warningSigns,
      hasEvidence: hasEvidence,
      evidenceNoteEn: hasEvidence
        ? "Warning signs with evidence from your message:"
        : "Not enough evidence of scam tactics. The message does not create panic, ask for credentials, or use untrusted links.",
      evidenceNoteHi: hasEvidence
        ? "संदेश में मिले प्रत्यक्ष प्रमाणों के साथ चेतावनी संकेत:"
        : "धोखाधड़ी के पर्याप्त प्रमाण नहीं मिले। इस मैसेज में कोई हड़बड़ी, गोपनीय जानकारी की मांग या संदिग्ध लिंक नहीं है।",
      evidenceNoteBn: hasEvidence
        ? "মেসেজে পাওয়া প্রত্যক্ষ প্রমাণসহ সতর্কবার্তা লক্ষণ:"
        : "প্রতারণার কৌশলগত প্রমাণের অভাব রয়েছে। এই বার্তায় কোনো কৃত্রিম তাড়াহুড়ো, ওটিপি/পিন চাওয়া বা অচেনা লিঙ্ক নেই।",
      avoidEn: (info && info.avoidEn) || V.avoidEn || "",
      avoidHi: (info && info.avoidHi) || V.avoidHi || "",
      avoidBn: (info && info.avoidBn) || V.avoidBn || "",
      verifyEn: (info && info.verifyEn) || V.verifyEn || "",
      verifyHi: (info && info.verifyHi) || V.verifyHi || "",
      verifyBn: (info && info.verifyBn) || V.verifyBn || "",
      reportEn: (info && info.reportEn) || V.reportEn || "",
      reportHi: (info && info.reportHi) || V.reportHi || "",
      reportBn: (info && info.reportBn) || V.reportBn || "",
      spokenHi: "",
      spokenEn: "",
      spokenBn: "",
      debug: { categories: cats, signals: signals }
    };

    result.nextSteps = {
      avoidEn: result.avoidEn,
      avoidHi: result.avoidHi,
      avoidBn: result.avoidBn,
      verifyEn: result.verifyEn,
      verifyHi: result.verifyHi,
      verifyBn: result.verifyBn,
      reportEn: result.reportEn,
      reportHi: result.reportHi,
      reportBn: result.reportBn
    };

    if (verdict === "low_risk") {
      result.explanationHi = V.noteHi;
      result.explanationEn = V.noteEn;
      result.explanationBn = V.noteBn || V.noteEn;
      result.stepsHi = V.stepsHi.slice();
      result.stepsEn = V.stepsEn.slice();
      result.stepsBn = (V.stepsBn || V.stepsEn).slice();
    } else {
      result.explanationHi = info.explainHi;
      result.explanationEn = info.explainEn;
      result.explanationBn = info.explainBn || info.explainEn;
      result.stepsHi = info.stepsHi.slice();
      result.stepsEn = info.stepsEn.slice();
      result.stepsBn = (info.stepsBn || info.stepsEn).slice();

      Object.keys(cats).forEach(function (id) {
        if (cats[id].score >= W.medium) {
          result.reasonsHi.push(RULES.categories[id].reasonHi);
          result.reasonsEn.push(RULES.categories[id].reasonEn);
          result.reasonsBn.push(RULES.categories[id].reasonBn || RULES.categories[id].reasonEn);
        }
      });
      signals.forEach(function (s) {
        result.reasonsHi.push(G.labelsHi[s.id]);
        result.reasonsEn.push(G.labelsEn[s.id]);
        result.reasonsBn.push((G.labelsBn && G.labelsBn[s.id]) || G.labelsEn[s.id]);
      });
    }

    result.spokenHi = [result.headlineHi, result.explanationHi].concat(result.stepsHi.slice(0, 2)).join(" ");
    result.spokenEn = [result.headlineEn, result.explanationEn].concat(result.stepsEn.slice(0, 2)).join(" ");
    result.spokenBn = [result.headlineBn, result.explanationBn].concat(result.stepsBn.slice(0, 2)).join(" ");
    return result;
  }

  var api = { analyze: analyze, normalize: normalize, tokenize: tokenize };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.ScamSaathi = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
