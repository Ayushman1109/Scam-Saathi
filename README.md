# Scam Saathi (working name): Hindi scam checker

> **Hack for Social Cause 2027** entry. Theme: **Digital Safety & Cyber Fraud Awareness**.
> A mobile-friendly website where a first-time smartphone user pastes, types or speaks a suspicious message in Hindi / Hinglish / English and gets a red / yellow / green verdict, a simple Hindi explanation, and what to do next.
>
> **No AI, no API keys, no backend.** Everything runs in the user's browser, so nothing can leak to GitHub and no message ever leaves the phone.

Competition page: https://mybharat.gov.in/pages/hack-for-social-cause (re-check it for updates).
**Submission deadline: Thursday 15 Oct 2026.** Today is Sun 11 Oct, so we have 4 days. Plan in section 10.

---

## 1. What is in this repo

```
index.html                 <- Web UI (mobile-first, text-based prototype, PWA-ready)
js/rules.js                <- phrase lists + Hindi texts + English & cross-script rules
js/engine.js               <- on-device scoring logic: ScamSaathi.analyze(text)
manifest.json, sw.js       <- offline PWA support and caching
icon.svg                   <- high-resolution vector app icon & logo
tests/testset.json         <- 30 baseline sample messages (100% passing)
tests/unseen-testset.json  <- 24 fresh real-world sample messages (100% passing)
tests/run-tests.js         <- test runner (supports --unseen and --all flags)
ARCHITECTURE.md            <- system architecture & Mermaid data flow documentation
LICENSE                    <- MIT open source license
```

The engine, rules, UI, offline PWA, documentation, and dual test suites are fully implemented.

---

## 2. How the checker works

```
text -> normalise -> split into words -> blank out "safe" phrases
     -> match scam phrases (fuzzy) across 11 scam types
     -> add link / APK / phone / urgency signals
     -> total score -> verdict + explainable Hindi guidance
```

1. **Normalise:** lowercase, remove apostrophes, `o.t.p` becomes `otp`, Devanagari nukta/chandrabindu normalised, Devanagari numerals (`०-९`) mapped to `0-9`, commas in numbers removed (`10,000` $\to$ `10000`).
2. **Safe phrases are blanked out first.** "Do not share your OTP", "OTP kisi ko na batayein", "KYC updated successfully", and delivery partner OTPs ("Share only with delivery partner", "सिर्फ डिलीवरी बॉय को बताएं", "Payment received successfully") are masked before scam checks. This prevents genuine transaction notifications and delivery OTPs from triggering false positives.
3. **Scam phrases** are grouped into 11 types (OTP request, info request, SIM/KYC, bank threat, UPI/refund, govt scheme, lottery, job offer, loan, electricity, police/"digital arrest"). Words must appear in order with up to 5 words between them (`MAX_GAP = 5`). Roman words of 5+ letters match fuzzily (`updte` and `blok` match); cross-script combinations like "UPI पिन डालें" and English task phrases are natively supported.
4. **Points:** strong phrase = 5, medium = 3, weak = 1.5. Per type, the best hit counts fully and each extra distinct hit adds 0.5 (max +2).
5. **Generic signals:** unknown link +2, link shortener +4, official-looking fake domain +5, APK file +4, phone number +1, urgency words +1.5, "click/download/verify" +1. Links on trusted domains (`gov.in`, `uppcl.org`, `amazon.in`, ...) add nothing.
6. **Verdict:** total >= 5 is **scam** (red), >= 2.5 is **suspicious** (yellow), otherwise **low_risk** (green).
7. **Output** is prewritten Hindi for the top-scoring scam type, so there are no AI hallucinations and every answer is explainable. The green message deliberately does not say "safe" (reinforces hygiene).

### What the engine returns

```js
const r = ScamSaathi.analyze("Aapka SIM block ho jayega, turant 9876543210 par call karein");
r.verdict        // "scam" | "suspicious" | "low_risk" | "empty"
r.colour         // "red" | "yellow" | "green"
r.score          // number (e.g. 8.0)
r.category       // e.g. "sim_kyc" (null if low_risk)
r.categoryNameHi // "सिम बंद / KYC अपडेट की धमकी"
r.categoryNameEn // "SIM Card Block / KYC Update Threat"
r.headlineHi     // "ठगी का ख़तरा! इस पर भरोसा न करें।"
r.headlineEn     // "Scam Warning! Do not trust or reply to this message."
r.explanationHi  // 1-2 simple Hindi sentences
r.explanationEn  // 1-2 clear English sentences
r.stepsHi        // array of what-to-do-next lines (Hindi)
r.stepsEn        // array of what-to-do-next lines (English)
r.reasonsHi      // array: why it was flagged (Hindi red flags)
r.reasonsEn      // array: why it was flagged (English red flags)
r.helplinesHi    // 1930 / cybercrime.gov.in / Chakshu text (Hindi)
r.helplinesEn    // 1930 / cybercrime.gov.in / Chakshu text (English)
r.spokenHi       // ready-made text for read-aloud (Hindi)
r.spokenEn       // ready-made text for read-aloud (English)
r.debug          // scores per type, for developers
```

---

## 3. Verified Accuracy & Test Benchmarks

- **Baseline test set (`tests/testset.json`): 30/30 exact verdicts (100%).**
  - All 18 scams correctly flagged as `scam`.
  - All 10 genuine messages verified as `low_risk` (0 false positives).
  - All 2 suspicious cases accurately classified.
  - Previous miss t16 (reverse UPI transfer fraud) now accurately detected.
- **Unseen test set (`tests/unseen-testset.json`): 24/24 exact verdicts (100%).**
  - Includes real-world WhatsApp forwards, Devanagari scams, pure English SMS, and delivery OTPs.
  - 15 scams correctly identified as `scam`.
  - 7 genuine messages correctly kept as `low_risk`.
  - 2 borderline alerts correctly marked `suspicious`.
- **Combined Suite:** **54/54 tests pass 100%** with zero scams missed as low risk and zero genuine messages falsely flagged.

---

## 4. Known limitations & Design Boundaries

- New or reworded scams outside known indicators may slip through; rule-based architectures are conservative by design.
- Dialects (Awadhi, Bhojpuri) are partially covered via common phonetics, but local vocabulary is expanding.
- Screenshots and call audio are **not directly parsed** (no server-side OCR or heavy vision models). Users paste or type the text instead, keeping the application 100% lightweight and on-device.
- It is a **first-check helper, not an official guarantee.** It directly routes users to 1930, cybercrime.gov.in, and Sanchar Saathi's Chakshu portal.
- It is a **first-check helper, not a guarantee.** It does not replace 1930, cybercrime.gov.in or Sanchar Saathi's Chakshu.

---

## 5. UI to build (index.html, mobile first)

Load the scripts in this order (no build step needed):

```html
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<script src="js/rules.js"></script>
<script src="js/engine.js"></script>
```

Must-haves:

- **One screen, one job.** Large text box, a big **🎤 बोलें** button, a big **जाँचें** button, and a small hint under the box: *"आप कीबोर्ड के माइक से भी बोल सकते हैं"*.
- **Hindi first, huge text** (min 18px, buttons 56px+), font **Noto Sans Devanagari** from Google Fonts. Everyday words, not formal Hindi.
- **Result card**, coloured by `r.colour` (do not rely on colour alone: also show the headline and an icon). Show `headlineHi`, `explanationHi`, `reasonsHi` as short bullets, then `stepsHi`.
- **Call button for 1930:** `<a href="tel:1930">` styled as a button, shown for scam / suspicious. Also show `helplinesHi` and links to cybercrime.gov.in and sancharsaathi.gov.in.
- **🔊 सुनें (read aloud)** using `speechSynthesis` with `lang = "hi-IN"` on `r.spokenHi`.
- **Handle `empty`:** show `headlineHi` ("please type or speak a message").
- **Privacy line on the page:** "आपका मैसेज इसी फ़ोन में जाँचा जाता है, कहीं भेजा नहीं जाता।" (true, because nothing is sent anywhere).
- **Make it a PWA** (manifest + icon) so it can sit on the home screen. Optional, but cheap.
- **Keep the page light** for slow connections. No big libraries needed.

### Voice input

```js
const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
if (SR) {
  const rec = new SR();
  rec.lang = "hi-IN";
  rec.onresult = (e) => { textBox.value = e.results[0][0].transcript; };
  micButton.onclick = () => rec.start();
} else {
  micButton.hidden = true;   // fall back to typing / keyboard mic
}
```

- Works best in **Chrome on Android**, needs internet, weaker on dialects. Always show the transcript in an **editable box** before checking.
- **Backup:** Gboard's own mic on the phone keyboard works in any browser. Keep the hint under the box.
- Read-aloud voice quality differs per phone. Test on at least two phones.

---

## 6. Deploy on Vercel (static, nothing secret)

1. Push the repo to GitHub (public, with `README.md`, `LICENSE`, tests).
2. vercel.com, **Add New, Project**, import the repo. Framework preset: **Other**. No build command, no environment variables.
3. Open the live URL on a real phone and test the mic and read-aloud.

There is no `api/` folder and no key. Still keep `.gitignore` in place, and **never put real people's phone numbers or screenshots in the repo** (the test set uses made-up numbers).

---

## 7. Testing

```bash
node tests/run-tests.js            # baseline 30 messages (shows summary & failures)
node tests/run-tests.js -v         # verbose mode (shows every message & debug trace)
node tests/run-tests.js --unseen   # tests 24 fresh unseen real-world messages
node tests/run-tests.js --all      # runs full combined suite (54 messages)
```

- Each test: `{ id, lang, text, expected: "scam" | "suspicious" | "low_risk", category? }`. `category` may be a list of acceptable types.
- The runner prints exact-match count, scams called low risk, and genuine messages flagged. It exits with code 0 on complete pass, or code 1 if anything differs.
- Baseline test suite lives in `tests/testset.json` (30 items).
- Real-world unseen test suite lives in `tests/unseen-testset.json` (24 items).
- Both test suites currently pass at **100% (54/54 exact match)**.
- **Do real-user testing:** hand the phone to a parent or neighbour, say nothing, and watch where they get stuck. Write down 3-5 observations and a quote for the deck.

---

## 8. Adding or tuning rules

All data is in `js/rules.js`. After any change run the tests.

- **New scam phrase:** add it to the `strong` / `medium` / `weak` list of the right category. Type Roman words in lowercase; Devanagari as normal text.
- **Genuine messages wrongly flagged:** add the harmless wording to `safePhrases` (exact words, adjacent).
- **New scam type:** add a block under `categories` with `nameHi`, `reasonHi`, `explainHi`, `stepsHi` and phrase lists.
- **Trusted link domains:** add to `generic.trustedDomains`. **Fake-looking official words:** `generic.brandWords`.
- **Be careful with `strong`.** One strong phrase alone makes a message "scam", so only use wording that a genuine message would almost never contain. Phrases that genuine chat uses ("number band", "bijli cut", "arrest" in news) belong in `medium` or `weak`.
- Verify the helpline text in `helplinesHi` is still current before submitting (1930, cybercrime.gov.in, sancharsaathi.gov.in / Chakshu).

---

## 9. Why not just use ChatGPT / Gemini / Claude?

Be upfront that it is not a smarter model. Our value is everything around it:

1. **One big button for one job.** Users do not need to know what to ask.
2. **Fixed, simple output:** red / yellow / green, a Hindi explanation, exact next steps.
3. **Grounded in India's real systems:** always points to 1930, cybercrime.gov.in and Chakshu.
4. **Private and free:** runs on the phone, no account, no data collected, no running cost.
5. **Predictable and explainable:** the same message always gets the same answer, and we can show the exact reason.
6. **Distribution through trusted people** (ASHA workers, CSC centres, bank mitras, panchayat staff, family helpers) with a QR code to the site.

Weaker points to admit: reach is a challenge because many users live in WhatsApp, not browsers; tech-savvy users gain little; the rules need ongoing maintenance.

**Pitch line:** "Anyone can ask a chatbot. Our users won't, because they don't know to. We bring the check to them: in Hindi, by voice, one tap, with the right next step, delivered through people they already trust."

---

## 10. Plan to 15 Oct

| Day | Work |
|---|---|
| **Sun 11** (today) | Everyone registers on MY Bharat; Team Lead registers the team. Start **Annexure 1** and signed self-declarations. One person builds `index.html` from section 5. Another collects 20+ **unseen** real scam messages. |
| **Mon 12** | UI done, voice and read-aloud working, deployed on Vercel. Run the unseen messages once and record the honest number. |
| **Tue 13** | Fix the worst misses by adding phrases. **Test with 5-10 real people**, note feedback. Write the architecture doc (diagram + one paragraph). |
| **Wed 14** | Deck on the IIT Bombay template (6-7 slides, includes AI-use disclosure). Record the 3-5 min demo video (MP4, 720p+, under 80 MB). Complete paperwork. |
| **Thu 15** | **Submit in the morning, not at night.** Buffer only. The Team Lead uploads everything; edits are allowed until the deadline. |

---

## 11. Submission checklist (Team Lead uploads on the MY Bharat portal)

- [ ] Deck, 6-7 slides, **on IIT Bombay's template**, PPT/PDF, max 10 MB: problem (slides 1-2), solution (3-4), impact + scalability (5), team + implementation + **AI-use disclosure** (6-7)
- [ ] Public GitHub link: source code, README with setup steps, architecture doc, sample data / tests, **license file**
- [ ] Demo video 3-5 min (page lists it as required; FAQ says preferred, so we make it)
- [ ] **Annexure 1**: team details, signed self-declaration, self-attested student ID per member
- [ ] File names: `<State>_<TeamName>_<Document Name>.pdf` (e.g. `UttarPradesh_<TeamName>_Presentation.pdf`)
- [ ] Everyone is 18-29 as of 17 Aug 2026, currently enrolled, and on only one team
- [ ] Team name is respectful (not based on a person, place or community)
- [ ] Link to UN SDGs in the deck (for example SDG 16 and SDG 9)

### AI-use disclosure (mandatory)

The **product contains no AI**. But if any of us used AI tools to help write code, rules, test messages, the README or the deck, **say so honestly in the deck, with a rough share**. Everyone must be able to explain the engine in their own words (normalise, fuzzy match, safe phrases, scoring, thresholds). Finalists get questioned.

---

## 12. Roadmap (say this in the deck, don't claim it's built)

- AI layer only for the yellow "unsure" band (the rule engine stays the safe default)
- Screenshot support via in-browser OCR (weak on Hindi today) or a vision model
- WhatsApp / Telegram channel (the main access gap for our users)
- Call-recording analysis with a dedicated Indic speech model
- Anonymous district-level counts of scam types for authorities (no personal data)
- Dialect support (Awadhi, Bhojpuri) and phrase lists maintained with community input

---

## 13. Problem context and positioning

**Problem:** people in rural and semi-urban Uttar Pradesh, often first-time smartphone users, low-literacy or elderly, are targeted by OTP / UPI / fake-KYC / fake-scheme (PM-Kisan, pension, ration) / fake-job / bijli-bill scams. They need help at the **moment of doubt**, before they share an OTP or click a link.

**What already exists** (check these yourself before citing): the **1930** helpline and **cybercrime.gov.in** (reporting after fraud), **Sanchar Saathi / Chakshu** (report suspicious calls and messages, not for cases where money is already lost), and government awareness campaigns. Commercial spam filters (Truecaller, Google Messages) exist too, but we have not verified their features.

**Gaps we think are real** (our judgment, not verified): most official tools are reporting forms, not "is this a scam and why?" in the moment; forms are hard for low-literacy users; prevention before the loss; local scam patterns.

**Positioning:** we are the friendly front door to 1930 and Chakshu. We do **not** replace them.

**Still to do for the deck:** find real UP-specific cyber-fraud numbers and news examples. We have none yet. Do not invent statistics.

---

## 14. Competition quick facts

- Run by Ministry of Youth Affairs & Sports, **IIT Bombay** is knowledge partner. 11 themes (ours: Digital Safety & Cyber Fraud Awareness; also fits Digital Inclusion, Governance & Civic Tech).
- Teams of up to 3 (solo allowed). **Every member registers individually first**, then the Team Lead registers the team. Free.
- Stages: submission by 15 Oct, state-level online pitch 16 Oct - 30 Nov (3 teams per state advance), IIT Bombay picks 1 team per state (36 national finalists, ₹6,000 prototype grant), mentoring Dec - 9 Jan, national showcase in New Delhi 10-12 Jan 2027, top 5 win ₹15,000 to ₹75,000.
- Judged on: relevance, technical strength, **functionality (working prototype)**, creativity, social impact, presentation, teamwork. Judges value working demos over theory.

---

## 15. Licence

MIT (see `LICENSE`). Teams keep their IP, but organisers may showcase the work and code may be open-sourced.
