# Scam Saathi (स्कैम साथी / স্ক্যাম সাথী) — System Architecture Specification

> **Project:** Scam Saathi  
> **Competition:** Hack for Social Cause 2027  
> **Theme:** Digital Safety & Cyber Fraud Awareness  
> **Knowledge Partner:** IIT Bombay  
> **Document Version:** 1.3 (Submission Release)

---

## 1. Architectural Philosophy & Design Principles

Scam Saathi is designed to address a critical structural vulnerability in India's digital ecosystem: the lack of accessible, in-the-moment cyber fraud verification for first-time smartphone users and vernacular language speakers.

The architecture is built upon three foundational tenets:

1. **Privacy-by-Architecture (Zero Data Leakage):**
   Conventional cloud-based scam checkers transmit user messages, financial notifications, and personal contact numbers to remote servers or third-party AI APIs. Scam Saathi guarantees 100% on-device execution. The user's message or uploaded screenshot never leaves their browser environment.

2. **Deterministic Explainability over Generative Hallucination:**
   Large Language Models (LLMs) can hallucinate, produce inconsistent verdicts for slightly altered text, and require expensive server infrastructure or API subscriptions. Scam Saathi utilizes a deterministic, rule-based scoring engine that produces reproducible, human-vetted explanations grounded in official Indian cyber safety guidelines.

3. **Universal Accessibility on Constrained Devices:**
   The application requires zero installation, functions on budget Android smartphones over 3G/4G connections, and operates offline via a Progressive Web App (PWA) service worker.

---

## 2. High-Level Data Flow Architecture

```mermaid
flowchart TD
    subgraph Ingestion Layer
        A1[Suspicious SMS / WhatsApp / Web Link]
        A2[Screenshot / Photo / Clipboard Image] -->|On-Device Tesseract.js WASM\neng + hin + ben| A1
    end

    subgraph Preprocessing & Normalization
        A1 --> B1[NFC Normalization & Zero-Width Stripping]
        B1 --> B2[Indic Script Normalization\nDevanagari & Bengali Numerals ०-৯ to 0-9]
        B2 --> B3[Digit Comma Removal\n'10,000' to '10000']
        B3 --> B4[Tokenization & Punctuation Condensation]
    end

    subgraph Protective Masking
        B4 --> C1[Safe-Phrase Matching Pass\nBank Advice, Delivery OTP & Utility Receipts]
        C1 --> C2[Masked Token Stream\nMatched Safe Tokens Replaced with '_']
    end

    subgraph Heuristic Evaluation Engine
        C2 --> D1[11 Scam Categories Matcher\nFuzzy Levenshtein + Window Gap = 5]
        C2 --> D2[Generic Risk Extractors\nLinks, Shorteners, Lookalikes, APKs, Urgency, Phone]
        D1 --> E1[Category Score Aggregation\nBest Hit + Diminishing Returns]
        D2 --> E2[Generic Risk Score Aggregation]
        E1 --> F[Total Risk Score Calculation]
        E2 --> F
    end

    subgraph Clue & Evidence Extraction
        F --> G1[4 Warning Sign Analyzers\nUrgency, Credentials, Untrusted Links, APK/Numbers]
        G1 --> G2[Evidence Quoting Engine\nDirect Message Snippets & Citations]
    end

    subgraph 3-Question Defensive Guidance
        G2 --> H1[🛑 1. What to Avoid Right Now]
        G2 --> H2[🔍 2. What to Verify Independently]
        G2 --> H3[🚨 3. Where to Report / Seek Help\n1930 & cybercrime.gov.in / Chakshu]
    end

    subgraph Multilingual Presentation Layer
        H1 --> I[Trilingual Real-Time UI\nHindi | English | Bengali]
        H2 --> I
        H3 --> I
    end
```

---

## 3. Pipeline Implementation Details

### 3.1 Normalization & Tokenization Pipeline
Before evaluating any text against threat patterns, Scam Saathi applies a comprehensive seven-stage normalization pipeline in [engine.js](js/engine.js):

1. **Unicode NFC & Obfuscation Stripping:** Normalizes combining characters and removes zero-width spaces (`\u200B`, `\u200C`, `\uFEFF`) commonly used by scammers to defeat keyword filters.
2. **Indic Script & Numeral Normalization:** 
   - Strips nuktas (`़`) and normalizes chandrabindu (`ँ` $\to$ `ं`).
   - Translates both Devanagari numerals (`०-९`, `\u0966-\u096F`) and Bengali numerals (`০-৯`, `\u09E6-\u09EF`) into standard ASCII numerals (`0-9`). This enables uniform evaluation of dates, monetary amounts, and 10-digit telephone numbers irrespective of script.
3. **Digit Grouping Protection:** Normalizes thousands-separators in amounts (`10,000` $\to$ `10000`, `₹ 25,00,000` $\to$ `2500000`) so that amounts are not split into distinct tokens.
4. **Delimited Acronym Condensation:** Collapses dotted, dashed, slashed, and underscored acronyms (`o.t.p`, `o-t-p` $\to$ `otp`, `k.y.c`, `k-y-c` $\to$ `kyc`, `u-p-i` $\to$ `upi`).
5. **Apostrophe & Character Elongation Trimming:** Replaces contractions (`don't` $\to$ `dont`) and limits repeated emotional characters (`bhejooo` $\to$ `bhejoo`).
6. **Anti-Evasion Leetspeak Deobfuscation:** Restores adversarial phonetic and number substitutions for high-risk scam triggers (`c1ick`, `cl1ck` $\to$ `click`, `0tp` $\to$ `otp`, `p1n` $\to$ `pin`, `s1m` $\to$ `sim`, `k¥c` $\to$ `kyc`, `bl0ck` $\to$ `block`, `d0wnl0ad` $\to$ `download`).
7. **Unicode Token Segmentation:** Uses Unicode property escapes (`\p{L}\p{M}\p{N}`) to cleanly split multi-lingual text across Latin, Devanagari, and Bengali scripts.

### 3.2 Safe-Phrase Masking (False-Positive Prevention)
A persistent flaw in rudimentary scam scanners is flagging authentic transactional alerts. For instance:
> *"Your Swiggy delivery OTP is 4829. Share it only with the delivery partner upon arrival."*  
> *"Rs 2000 has been credited to your bank account ending 4321 under 17th installment. -Govt of India (pmkisan.gov.in)"*  
> *"বিদ্যুৎ বিল জমা হয়েছে। রসিদ ডাউনলোড করতে লগইন করুন wbsedcl.in"*  
> *"Never share your OTP or NetBanking password with anyone. -SBI"*

All of these messages contain sensitive keywords like `"OTP"`, `"bank account"`, or scheme names. To eliminate false alarms, the engine runs an initial **safe-phrase masking pass** using a curated dictionary in [rules.js](js/rules.js) (`RULES.safePhrases`):
* Includes English, Hinglish, Hindi, and Bengali transactional and safety phrases: `"do not share"`, `"never share your otp"`, `"share only with delivery partner"`, `"share otp with postman upon delivery"`, `"has been credited to your bank account"`, `"सब्सिडी सफलतापूर्वक जमा कर दी गई"`, `"বিদ্যুৎ বিল জমা হয়েছে"`, `"telecom advisory"`, `"trai does not disconnect"`.
* **Length-Descending Precedence:** Safe phrases are sorted by token count descending before matching. This ensures longer, highly specific transactional clauses (such as `"has been credited to your bank account ending"`) are masked atomically before shorter subphrases can fragment them.
* When a safe phrase is detected, its constituent tokens are masked out with `_` **before** the scam classification rules evaluate the stream.
* Result: Authentic delivery notifications, government direct-benefit credits, and official bank advisories consistently score `0.0` or remain well below the suspicion threshold.

### 3.3 Multi-Word Phrase Matching with Natural Window Gap (`MAX_GAP = 5`)
Indian scam messages naturally intersperse threat verbs with dates, amounts, and app names:
> *"Aapka electricity connection **aaj raat 9:30 baje cut** kar diya jayega"*  
> *"Sir galti se **aapke Paytm mein 10000 rupaye transfer** ho gaye"*  
> *"আপনার বিদ্যুৎ বিল বকেয়া থাকায় **আজ রাত বিদ্যুৎ সংযোগ বিচ্ছিন্ন** করা হবে"*

A rigid exact-substring check would fail to match these variations. Scam Saathi implements an ordered multi-word token finder:
* Tokens of the target phrase must appear in proper sequence.
* Intervening words up to a window gap of **5 tokens** (`MAX_GAP = 5`) are permitted between words.
* This allows natural sentence structures (amounts, dates, app names) to match without explosive combinatorial rule definitions.

### 3.4 Fuzzy Token Matching (Levenshtein Distance)
To prevent deliberate typo evasion (e.g., `updte` for `update`, `blok` for `block`):
* Roman words of 5 to 7 letters allow a Levenshtein edit distance of $\le 1$.
* Roman words of 8 or more letters allow a Levenshtein edit distance of $\le 2$.
* Words of 4 letters or fewer, numerical digits, and short Devanagari words require exact matching to prevent false collisions (e.g., distinguishing `bank` from `band`).

---

## 4. Scoring Heuristics & Mathematical Formulation

### 4.1 Weight Distribution
Phrases are categorized into three severity tiers in [rules.js](js/rules.js):
* **Strong ($W_{\text{strong}} = 5.0$):** High-confidence fraud indicators that immediately cross the scam threshold on their own (e.g., *"enter UPI pin to receive"*, *"digital arrest summons"*, *"power cut tonight contact 98..."*).
* **Medium ($W_{\text{medium}} = 3.0$):** Suspicious phrases that warrant caution and trigger a scam verdict when combined with secondary indicators (e.g., *"SIM block"*, *"KBC lucky draw"*, *"account suspended"*).
* **Weak ($W_{\text{weak}} = 1.5$):** Ambiguous urgency or action requests (e.g., *"urgent action required"*, *"verify today"*).

### 4.2 Category Score Aggregation with Diminishing Returns
Within any individual scam category $c$, multiple phrase hits are aggregated using a diminishing returns formula:

$$\text{Score}_c = \text{Score}_{\text{primary}} + \min\left(2.0, \, 0.5 \times (N_{\text{hits}} - 1)\right)$$

Where $\text{Score}_{\text{primary}}$ is the weight of the highest-severity matched phrase, and each additional distinct hit contributes $0.5$ up to a maximum cap of $+2.0$. This prevents a single repetitive message from artificially skewing internal category dominance while still rewarding multi-signal confirmation.

### 4.3 Generic Signal Modifiers
Independent of specific scam categories, generic structural red flags add modifier points:

| Signal Indicator | Weight | Detection Criteria |
| :--- | :---: | :--- |
| **Lookalike Domain** | $+5.0$ | Untrusted URL containing brand terms (`sbi`, `kyc`, `discom`, `aadhaar`) |
| **Android APK Attachment** | $+4.0$ | Mentions `.apk` download or sideloading links |
| **Link Shortener** | $+4.0$ | URLs matching known shortener hosts (`bit.ly`, `tinyurl.com`, `is.gd`, etc.) |
| **Unverified URL** | $+2.0$ | Any HTTP/HTTPS link not belonging to `RULES.generic.trustedDomains` |
| **Artificial Urgency** | $+1.5$ | Words inciting immediate panic (*"turant"*, *"tonight"*, *"आज ही"*, *"24 hours"*) |
| **Unsolicited Phone** | $+1.0$ | Standard 10-digit Indian mobile telephone numbers |
| **Imperative Call-to-Action** | $+1.0$ | Prompts to click, download, or message on WhatsApp |

*Trusted Domains Bypass:* URLs resolving to verified Indian public infrastructure (`gov.in`, `nic.in`, `uppcl.org`, `sbi.co.in`, `npci.org.in`, `amazon.in`, etc.) incur $0$ penalty points.

### 4.4 Verdict Thresholds
The total score $S_{\text{total}}$ is evaluated against calibrated boundaries:

$$S_{\text{total}} = \sum_{c} \text{Score}_c + \sum \text{Signals}$$

$$\text{Verdict} = \begin{cases} 
\text{SCAM (Red Alert)} & \text{if } S_{\text{total}} \ge 5.0 \\
\text{SUSPICIOUS (Yellow Alert)} & \text{if } 2.5 \le S_{\text{total}} < 5.0 \\
\text{LOW RISK (Green Guidance)} & \text{if } S_{\text{total}} < 2.5 
\end{cases}$$

---

### 4.5 Warning Signs & Evidence Quoting Engine
Users need to understand *why* a message is risky, backed by concrete evidence rather than an arbitrary verdict badge. In [engine.js](js/engine.js) (`extractWarningSigns`), the engine scans the text and matches explicit quotes against four distinct threat dimensions:

1. **Urgency & Coercive Threats:** Quotes language threatening immediate disconnection, account suspension, or legal arrest (e.g., `"power will be disconnected tonight"`, `"আজ রাত বিদ্যুৎ সংযোগ বিচ্ছিন্ন"`).
2. **Credential & Payment Requests:** Quotes requests for OTPs, PINs, passwords, or reverse-transfer refunds (e.g., `"enter upi pin to receive"`, `"otp share করুন"`).
3. **Unfamiliar Links & Unrealistic Rewards:** Extracts unverified URLs, link shorteners, or unsolicited lottery claims (e.g., `"bit.ly/claim"`, `"২৫ লক্ষ টাকা লটারি জিতেছেন"`).
4. **Malicious App Installs & Personal Numbers:** Extracts `.apk` downloads, personal 10-digit mobile phone numbers, or WhatsApp redirect requests.

**Transparent Evidence Fallback:** If the message is a genuine alert or utility receipt and no predatory patterns are triggered, the engine explicitly confirms:  
> *"Not enough evidence of scam tactics. The message does not create panic, ask for credentials, or use untrusted links."* (Available in English, Hindi, and Bengali).

---

### 4.6 Safe, Specific Next Steps Framework (3-Question Paradigm)
To prevent cognitive overload during stressful moments, Scam Saathi organizes defensive actions around three essential citizen questions:

1. **🛑 1. What should I avoid doing right now?**
   Concrete prohibitions (e.g., *"Do not share your OTP or password"*, *"Do not call the phone number mentioned in the message"*, *"Do not click the link or install any APK file"*).
2. **🔍 2. What should I verify independently?**
   Independent verification avenues (e.g., *"Check your electricity bill status directly on your official power company portal or office"*, *"Contact your bank branch using the number printed on your debit card"*).
3. **🚨 3. Where can I report it or seek help?**
   National public safety escalation:
   - **Financial Fraud Helpline:** Prompt guidance to call **1930** immediately for golden-hour payment freezing.
   - **National Cyber Crime Portal:** Online complaints via **cybercrime.gov.in**.
   - **DoT Sanchar Saathi Chakshu:** Citizen reporting of fraudulent SMS and spoofed phone numbers via **sancharsaathi.gov.in/sfc/**.

---

## 5. Multimodal On-Device OCR Architecture

To inspect screenshots and forwarded flyers without cloud servers:

1. **Lazy Loading:** The OCR library (Tesseract.js v5 WebAssembly) is dynamically imported only upon the first user interaction (file select, drag-and-drop, or `Ctrl+V` paste). Initial page load footprint remains lightweight (~50 KB).
2. **Worker Isolation:** The OCR engine executes inside a dedicated Web Worker thread. Heavy pixel computation never blocks the main UI thread, preserving a smooth 60fps frame rate.
3. **Trilingual Recognition Catalog:** The worker initializes with `eng+hin+ben`, extracting Devanagari text, Bengali script, and English/Hinglish alphanumeric characters simultaneously.
4. **Fuzzy Resiliency:** OCR extractions on low-resolution phone screens frequently introduce minor character artifacts (e.g., `0` misread as `O`, or `l` as `1`). Scam Saathi's fuzzy Levenshtein matcher naturally absorbs these character variances without degrading classification accuracy.

---

## 6. Threat Model & Privacy Analysis

| Threat / Risk Vector | Threat Analysis | Scam Saathi Mitigation |
| :--- | :--- | :--- |
| **Data Harvesting & Leakage** | Cloud scam checkers expose citizen phone numbers, bank names, and SMS contents to servers or model training sets. | **100% Zero-Network Execution.** All preprocessing, OCR, and classification execute locally in browser memory. No network packets are dispatched during analysis. |
| **Generative Hallucination** | LLM-based solutions can invent contradictory reasons or provide insecure advice when jailbroken. | **Deterministic Rule Catalog.** Verdicts, explanations, and advice checklists are pre-vetted by cyber safety standards. The same input always produces the exact same verdict. |
| **Adversarial Typo Evasion** | Attackers introduce intentional spelling mistakes (`updte KYC`, `blck SIM`). | **Levenshtein Fuzzy Matching.** Word matching accommodates distance $\le 1$ / $\le 2$ on vocabulary tokens of length $\ge 5$. |
| **Phishing Domain Masking** | Attackers disguise malicious links behind shorteners or lookalike URLs (`sbi-update.xyz`). | **Heuristic Domain Engine.** Analyzes URLs against whitelist of genuine domains (`gov.in`, `sbi.co.in`, `wbsedcl.in`, etc.) and penalizes lookalikes (+5.0) and shorteners (+4.0). |
| **Denial of Service / Offline Outages** | Mobile networks in rural/semi-urban areas often experience dropouts. | **PWA Service Worker.** Caches core scripts and markup locally, ensuring full functionality even with zero active internet access. |

---

## 7. Automated Test & Validation Harness

The codebase enforces continuous regression testing through `tests/run-tests.js`:

```
========================================================================
 Scam Saathi Automated Verification Suite
========================================================================
 Running Baseline Test Suite (tests/testset.json)...
 [PASS] 30/30 baseline scenarios verified.
 
 Running Real-World Unseen Suite (tests/unseen-testset.json)...
 [PASS] 62/62 real-world scenarios verified (including Bengali vectors).
------------------------------------------------------------------------
 Summary:
  Exact Verdict Match:            92 / 92 (100.0%)
  Scams Called Low Risk (Worst):  0 / 54  (0.0%)
  Genuine Messages Flagged:       0 / 34  (0.0%)
========================================================================
```

* **Zero Regressions Guarantee:** Tests cover Devanagari script, Bengali script, Hinglish phonetic spellings, delivery partner OTPs, electricity disconnection threats, digital arrest summons, e-challan APK packages, and authentic government DBT credit alerts.
* Any code modification that causes a genuine alert to trigger a false alarm or misses a high-risk scam immediately fails the automated runner with exit code `1`.
