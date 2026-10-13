/*  rules.js — ALL detection data lives here (no logic). Edit freely.
 *
 *  How phrases are matched (see engine.js):
 *   - A phrase is a few words that must appear IN ORDER in the message,
 *     with up to 4 other words allowed in between ("sim aaj raat block" matches "sim block").
 *   - Roman words of 5+ letters are matched fuzzily, so typos like "updte" or "blok" still match.
 *     Words of 4 letters or fewer, numbers, and short Devanagari words must match exactly.
 *   - Everything is lowercased and Devanagari is normalised (nukta / chandrabindu removed),
 *     so you can type phrases in plain form.
 *
 *  Weights:  strong = 5 points (a scam on its own), medium = 3, weak = 1.5.
 *  Verdict:  total >= 5 -> scam, >= 2.5 -> suspicious, else low_risk.
 */
(function (root) {
  "use strict";

  // Verbs meaning "send / tell / give" (English + Hinglish + Hindi). Used to build "asks for X" phrases.
  var ASK = [
    // English
    "share", "send", "enter", "provide", "give", "forward", "submit", "tell",
    // Hinglish
    "bhejiye", "bhejiyega", "bhejo", "bhejein", "bhej", "batao", "bataiye", "batayein", "bata",
    "dijiye", "dena", "dalein", "daliye", "daalo", "dalo", "dedo", "de do", "share karo", "send karo",
    // Hindi (Devanagari)
    "बताइए", "बताएं", "बताओ", "भेजिए", "भेजें", "भेजो", "दीजिए", "दीजिये", "डालें", "डालिए", "शेयर",
    "दें", "दो", "साझा करें", "साझा कीजिए", "दर्ज करें"
  ];

  // ask(["otp"]) -> ["otp bhejiye", "bhejiye otp", "otp batao", "batao otp", ...]
  function ask(nouns) {
    var out = [];
    nouns.forEach(function (n) {
      ASK.forEach(function (v) {
        out.push(n + " " + v);
        out.push(v + " " + n);
      });
    });
    return out;
  }

  var RULES = {
    thresholds: { scam: 5, suspicious: 2.5 },
    weights: { strong: 5, medium: 3, weak: 1.5 },

    // ---------------------------------------------------------------------------------
    // Phrases that CANCEL a match: "never share your OTP", "KYC updated successfully", delivery OTPs.
    // Matched exactly (no fuzzy). The matched words are blanked out before scoring.
    // ---------------------------------------------------------------------------------
    safePhrases: [
      // English
      "do not share", "dont share", "never share", "do not disclose", "dont disclose", "never disclose",
      "not to share", "will never ask", "never ask", "never asks", "never call", "never calls",
      "do not click", "dont click", "do not respond", "do not share with anyone", "dont share with anyone",
      "bank never asks", "bank will never ask", "never share your otp", "never share your password",
      "never share your netbanking password", "does not ask for your otp", "will never ask for confidential",
      "share only with delivery", "share it only with delivery", "share with delivery partner",
      "share with the delivery partner", "only with delivery partner", "only share with delivery",
      "share otp with delivery", "with delivery partner",
      "share otp with postman", "share with postman", "with postman upon delivery", "with postman",
      "kyc updated", "kyc is updated", "kyc has been updated", "kyc completed", "kyc is completed",
      "kyc has been completed", "kyc successful", "kyc verified", "kyc is verified",
      "bill paid successfully", "payment successful", "payment received successfully",
      "has been credited to your bank account ending", "has been credited to your bank account",
      "has been credited to your account ending", "has been credited to your account",
      "credited to your bank account ending", "credited to your account ending",
      "credited to your bank account", "credited to your account",
      "has been credited to your", "has been credited",
      "under 17th installment", "under installment",
      "verified details and pay on official portal", "pay on official portal",
      "track status on", "track status at", "check balance at",
      "otp for aadhaar authentication", "valid for 10 minutes do not share",
      "telecom advisory", "trai does not disconnect any mobile connection", "trai does not disconnect",
      "regarding sim disconnection", "calls regarding sim disconnection", "suspicious calls regarding sim disconnection",
      "verify with your service provider",
      "created successfully", "processed successfully", "has been processed successfully",
      "wish you a happy journey", "happy journey",
      "does not disconnect any mobile connection", "does not disconnect",
      // Hinglish
      "kisi ko na batayein", "kisi ko na bataye", "kisi ko na bataiye", "kisi ko na batayen",
      "kisi ko nahi batana", "kisi ko nahi batayein",
      "na batayein", "na bataiye", "na bataye", "na batayen",
      "share na karein", "share na kare", "share na kijiye",
      "mat bata", "mat batao", "mat batayein", "mat bhej", "mat bhejo", "mat bhejiye", "mat dena", "na dena",
      "kabhi nahi mangta", "kabhi nahi maangta", "kabhi nahi mangte", "kabhi nahi maangte", "kabhi na mange",
      "sirf delivery partner", "delivery agent ko hi", "delivery partner ko batayein", "delivery partner ko hi batayein",
      // Hindi (Devanagari)
      "किसी को न बताएं", "किसी को ना बताएं", "न बताएं", "ना बताएं", "न बताइए", "ना बताइए",
      "मत बताएं", "मत बताओ", "मत बताना",
      "साझा न करें", "साझा ना करें", "शेयर न करें", "शेयर ना करें",
      "क्लिक न करें", "क्लिक ना करें",
      "कभी नहीं मांगता", "कभी नहीं मांगते", "कभी नहीं मांगती", "कभी न मांगे",
      "किसी के साथ साझा न करें", "किसी के साथ शेयर न करें", "किसी से साझा न करें",
      "किसी को मत दें", "किसी को न दें", "बैंक कभी नहीं मांगता", "बैंक कभी नहीं पूछता",
      "कभी भी आपसे फोन या मैसेज पर ओटीपी", "कभी भी ओटीपी नहीं पूछता", "ओटीपी नहीं पूछता",
      "पासवर्ड नहीं पूछता", "सीवीवी नहीं पूछता", "कभी भी नहीं पूछता", "गोपनीय जानकारी न दें",
      "सिर्फ डिलीवरी पार्टनर", "सिर्फ डिलीवरी बॉय", "डिलीवरी पार्टनर को ही", "डिलीवरी पार्टनर के साथ साझा",
      "सफलतापूर्वक प्राप्त हुआ", "सफलतापूर्वक प्राप्त", "सफलतापूर्वक भुगतान", "सफलतापूर्वक जमा",
      "सफलतापूर्वक जमा कर दी गई", "सब्सिडी सफलतापूर्वक जमा", "खाते में सफलतापूर्वक जमा",
      "केवाईसी अपडेट हो गया", "केवाईसी पूरा हो गया"
    ],

    // ---------------------------------------------------------------------------------
    // Scam categories. Each has phrases (strong / medium / weak) and the Hindi text shown to the user.
    // ---------------------------------------------------------------------------------
    categories: {

      otp_request: {
        nameHi: "OTP / गुप्त कोड मांगना",
        nameEn: "OTP / Secret Code Request",
        reasonHi: "इसमें OTP या गुप्त कोड माँगा जा रहा है",
        reasonEn: "This message asks for an OTP or verification code",
        explainHi: "असली बैंक, सरकारी विभाग या कंपनी आपसे कभी OTP, पिन या गुप्त कोड नहीं मांगती। OTP बताते ही आपके खाते से पैसे निकल सकते हैं।",
        explainEn: "Authentic banks, government portals, and companies never ask for your OTP or verification code. Sharing your OTP can cause immediate unauthorized money withdrawals.",
        stepsHi: [
          "OTP, पिन या CVV किसी को न बताएं, चाहे वह खुद को बैंक वाला कहे।",
          "फ़ोन काट दें या मैसेज का जवाब न दें।",
          "अगर आप OTP बता चुके हैं, तो तुरंत 1930 पर कॉल करें।"
        ],
        stepsEn: [
          "Never share your OTP, PIN, or CVV, even if the sender claims to be a bank official.",
          "Disconnect the call or ignore and delete the message.",
          "If you have already shared an OTP, call national cyber helpline 1930 immediately."
        ],
        strong: ask(["otp", "ओटीपी"]).concat(ask(["verification code", "digit code", "सत्यापन कोड"])).concat([
          "share your otp", "enter the otp", "provide the otp", "enter otp to receive", "enter otp to get",
          "ओटीपी शेयर", "ओटीपी किसी को", "ओटीपी दर्ज करें", "ओटीपी दर्ज करो", "ओटीपी बताइए", "ओटीपी बताएं"
        ]),
        medium: [],
        weak: []
      },

      info_request: {
        nameHi: "निजी जानकारी मांगना",
        nameEn: "Personal / Financial Details Request",
        reasonHi: "इसमें पिन, पासवर्ड या निजी जानकारी माँगी जा रही है",
        reasonEn: "This message asks for your PIN, password, or sensitive details",
        explainHi: "आधार, पैन, कार्ड नंबर, पासवर्ड या पिन जैसी जानकारी मैसेज या फ़ोन पर माँगना ठगी का आम तरीका है। इससे आपके नाम पर धोखाधड़ी हो सकती है।",
        explainEn: "Asking for Aadhaar, PAN, card numbers, passwords, or PINs over message or call is a major sign of fraud. Scammers use this for identity theft and unauthorized debits.",
        stepsHi: [
          "अनजान व्यक्ति को आधार, पैन, कार्ड या बैंक की जानकारी न दें।",
          "बैंक से बात करनी हो तो कार्ड के पीछे लिखे असली नंबर पर खुद कॉल करें।"
        ],
        stepsEn: [
          "Never disclose Aadhaar, PAN, debit/credit card, or bank account details to unverified contacts.",
          "To contact your bank, call only the official phone number printed on the back of your card."
        ],
        strong: ask(["upi pin", "atm pin", "card pin", "debit card pin", "credit card pin", "cvv", "password", "netbanking password",
                     "पासवर्ड", "यूपीआई पिन", "एटीएम पिन", "सीवीवी", "upi पिन", "atm पिन"]).concat([
          "enter upi pin", "enter your upi pin", "enter atm pin", "enter password", "provide your pin", "provide your password",
          "कार्ड का सीवीवी", "पिन दर्ज करें", "पासवर्ड दर्ज करें", "यूपीआई पिन डालें"
        ]),
        medium: ask(["aadhaar number", "aadhar number", "adhar number", "aadhaar no", "aadhar no",
                     "pan number", "pan no", "card number", "bank details", "bank detail", "account number", "credit card number", "card details",
                     "आधार नंबर", "पैन नंबर", "कार्ड नंबर", "बैंक डिटेल", "बैंक डिटेल्स", "खाता नंबर", "अकाउंट नंबर", "खाता विवरण", "बैंक खाता विवरण", "कार्ड विवरण"]).concat([
          "verify on whatsapp", "verify your aadhaar on whatsapp", "verify aadhaar on whatsapp", "aadhaar verification on whatsapp",
          "व्हाट्सएप पर सत्यापित", "व्हाट्सएप पर वेरीफाई"
        ]),
        weak: []
      },

      sim_kyc: {
        nameHi: "सिम बंद / KYC अपडेट की धमकी",
        nameEn: "SIM Block / Fake KYC Threat",
        reasonHi: "इसमें सिम बंद होने या KYC अपडेट का डर दिखाया गया है",
        reasonEn: "This message threatens that your SIM or KYC will be blocked",
        explainHi: "ठग डराते हैं कि आपका सिम या खाता बंद हो जाएगा, ताकि आप जल्दबाज़ी में उनकी बात मानें। KYC के नाम पर आए अनजान लिंक या कॉल पर कोई जानकारी न दें।",
        explainEn: "Scammers create panic by claiming your SIM or account will be suspended today to force you into acting hurriedly. Never click unknown links or call unverified numbers for KYC.",
        stepsHi: [
          "दिए गए लिंक पर क्लिक न करें और दिए गए नंबर पर कॉल न करें।",
          "KYC के लिए सीधे अपने बैंक की शाखा या आधिकारिक ऐप पर जाएं।",
          "सिम की शंका हो तो अपनी कंपनी के असली कस्टमर केयर या दुकान पर पूछें।"
        ],
        stepsEn: [
          "Do not click the provided link and do not call the number mentioned in the message.",
          "For KYC updates, visit your bank branch directly or use the official verified bank app.",
          "For SIM concerns, visit an authorized telecom store or official company customer care."
        ],
        strong: [
          "sim block", "sim blocked", "sim band", "sim deactivate", "sim deactivated", "sim kat", "sim cut",
          "sim will be blocked", "sim card will be blocked", "sim will be deactivated", "sim suspended", "sim will be suspended",
          "सिम बंद", "सिम ब्लॉक", "सिम कट", "सिम डिएक्टिवेट", "सिम बंद हो जाएगा", "सिम ब्लॉक हो जाएगा", "सिम कार्ड बंद"
        ],
        medium: [
          "kyc update", "kyc expire", "kyc expired", "kyc pending", "kyc verify", "kyc verification",
          "kyc nahi", "e kyc update", "number band ho", "number block ho", "sim verification", "sim verification pending",
          "update kyc immediately", "complete your kyc", "complete kyc", "kyc verification pending", "update your aadhaar",
          "aadhaar suspicious activity", "suspicious activity verify", "verify on whatsapp",
          "केवाईसी अपडेट", "केवाईसी एक्सपायर", "केवाईसी पेंडिंग", "केवाईसी वेरिफिकेशन", "केवाईसी नहीं",
          "नंबर बंद हो", "नंबर ब्लॉक हो", "केवाईसी तुरंत करें", "केवाईसी सत्यापन", "केवाईसी अधूरा", "आधार अपडेट करें", "सिम वेरिफिकेशन"
        ],
        weak: ["kyc", "केवाईसी", "sim", "सिम"]
      },

      bank_threat: {
        nameHi: "बैंक खाता / कार्ड बंद होने की धमकी",
        nameEn: "Bank Account / Card Suspension Threat",
        reasonHi: "इसमें खाता, कार्ड या पैन बंद होने का डर दिखाया गया है",
        reasonEn: "This message threatens that your account, card, or PAN is blocked",
        explainHi: "खाता, ATM कार्ड या पैन बंद होने का डर दिखाकर जानकारी माँगना ठगी है। बैंक ऐसे मैसेज या कॉल पर जानकारी नहीं मांगता।",
        explainEn: "Using fear of account suspension or PAN deactivation to extract confidential credentials is fraud. Legitimate banks never ask for sensitive data via SMS or call.",
        stepsHi: [
          "लिंक न खोलें और कोई जानकारी न दें।",
          "अपने बैंक की शाखा जाएं या कार्ड के पीछे लिखे असली नंबर पर खुद कॉल करें।"
        ],
        stepsEn: [
          "Do not open the link and do not provide any confidential information.",
          "Visit your bank branch directly or call the official phone number on the back of your card."
        ],
        strong: [
          "account block", "account blocked", "account freeze", "account frozen", "account band",
          "account suspend", "account suspended", "account will be blocked", "account will be suspended", "account will be deactivated",
          "खाता बंद", "खाता ब्लॉक", "खाता फ्रीज", "अकाउंट बंद", "अकाउंट ब्लॉक", "अकाउंट फ्रीज", "खाता बंद हो जाएगा", "अकाउंट बंद हो जाएगा",
          "atm card block", "atm card blocked", "atm card band", "debit card block", "debit card blocked",
          "card band ho", "card block ho", "pan card block", "pan card blocked", "pan band", "card will be blocked",
          "पैन कार्ड ब्लॉक", "पैन कार्ड बंद", "एटीएम कार्ड बंद", "एटीएम कार्ड ब्लॉक", "पैन कार्ड बंद हो जाएगा", "खाता ब्लॉक कर दिया गया", "खाता फ्रीज कर दिया",
          "reward points worth", "reward points expiring", "reward points expire", "redeem reward points", "redeem points directly", "redeem points as cash",
          "fastag has been blacklisted", "fastag blacklisted", "fastag blocked", "update your fastag", "fastag kyc",
          "yono account is blocked", "sbi yono", "yono netbanking"
        ],
        medium: [
          "account closed", "account close", "pan update", "pan expire", "pan expired", "pan suspended", "pan card suspended",
          "update pan card", "link pan with account", "pan not linked", "pan aadhaar link", "unauthorized transaction",
          "bank se bol", "bank se call", "bank manager bol", "bank officer",
          "बैंक से बोल", "बैंक मैनेजर", "बैंक अधिकारी", "पैन अपडेट", "पैन कार्ड लिंक", "पैन लिंक करें", "खाता चालू रखने के लिए", "अकाउंट चालू रखने के लिए"
        ],
        weak: ["se bol raha", "se bol rahi", "se bol rha", "से बोल रहा", "से बोल रही", "bank account", "बैंक खाता"]
      },

      upi_refund: {
        nameHi: "UPI / QR कोड / रिफ़ंड का झांसा",
        nameEn: "UPI / Mistaken Transfer / QR Scam",
        reasonHi: "इसमें पैसे पाने के नाम पर पिन, QR कोड या रिक्वेस्ट का झांसा है",
        reasonEn: "This message uses fake money refunds, QR codes, or mistaken transfers as bait",
        explainHi: "पैसे पाने के लिए कभी पिन डालने या QR कोड स्कैन करने की ज़रूरत नहीं होती। पिन डालने पर पैसे आपके खाते से कटते हैं, आते नहीं।",
        explainEn: "You NEVER need to enter your UPI PIN or scan a QR code to receive money. Entering your PIN always deducts money from your account, it never credits money.",
        stepsHi: [
          "अनजान पेमेंट रिक्वेस्ट को Accept न करें और UPI पिन किसी को न बताएं।",
          "पैसे लेने के लिए पिन कभी न डालें।",
          "अगर पैसे कट गए हों तो तुरंत 1930 पर कॉल करें।"
        ],
        stepsEn: [
          "Never accept unverified payment requests and never enter your UPI PIN to receive money.",
          "If someone claims they sent money by mistake, check your official bank app balance first; never transfer money blindly.",
          "If money was debited, immediately call national cyber helpline 1930."
        ],
        strong: [
          "paise lene ke liye pin", "paise pane ke liye pin", "paisa pane ke liye pin", "paise aane ke liye pin",
          "pin dalte hi paise", "pin dalne par paise", "pin dalein paise aayenge", "pin daalein paise aayenge",
          "to receive money enter pin", "receive money enter upi pin", "to receive enter pin", "enter pin to receive",
          "enter upi pin to receive", "enter pin to receive money", "enter pin receive", "upi pin enter receive",
          "enter pin to get refund", "scan qr code to receive", "scan qr to get money", "accept request to receive money",
          "galti se transfer wapas", "galti se transfer ho gaye", "galti se paise wapas", "galti se transfer paisa wapas",
          "wrong transfer please return", "wrong transfer please refund", "sent money by mistake please return",
          "transferred money by mistake please return", "sent money by mistake send back", "sent by mistake please return",
          "पैसे पाने के लिए पिन", "पैसे लेने के लिए पिन", "पिन डालते ही पैसे", "पिन डालें पैसे आएंगे",
          "पैसे प्राप्त करने के लिए पिन", "पैसे मिलने के लिए पिन", "पैसे लेने के लिए upi pin", "पैसे पाने के लिए upi pin",
          "upi पिन डालें to receive", "upi pin डालें to receive", "पिन डालें to receive", "upi पिन डालें",
          "गलती से ट्रांसफर वापस", "गलती से पैसे वापस", "गलती से भेज दिया वापस", "गलती से ट्रांसफर हो गए"
        ],
        medium: [
          "qr code scan", "qr scan", "scan qr", "scan karke paise", "scan karein paise",
          "galti se paise", "galti se transfer", "galti se bhej", "wrong transfer",
          "request accept", "request approve", "collect request",
          "paisa wapas kar", "paise wapas kar", "paise wapas kardo", "refund link", "refund pin", "refund claim",
          "sent by mistake", "transferred by mistake", "money sent by mistake", "receive money enter pin",
          "click to receive refund", "refund approved",
          "क्यूआर कोड स्कैन", "क्यूआर स्कैन", "गलती से पैसे", "गलती से ट्रांसफर",
          "रिक्वेस्ट एक्सेप्ट", "रिक्वेस्ट अप्रूव", "पैसे वापस कर", "पैसे वापस कर दो", "पैसे वापस कर दीजिए", "पैसे वापस करें"
        ],
        weak: ["refund", "रिफंड", "cashback", "कैशबैक"]
      },

      govt_scheme: {
        nameHi: "सरकारी योजना के नाम पर ठगी",
        nameEn: "Fake Government Scheme / Subsidy Scam",
        reasonHi: "इसमें सरकारी योजना या सब्सिडी के नाम पर लालच या डर दिखाया गया है",
        reasonEn: "This message uses government welfare schemes or subsidies as bait",
        explainHi: "योजनाओं के नाम पर आए अनजान लिंक या APK फ़ाइल खोलने से आपका फ़ोन हैक हो सकता है और बैंक खाते से पैसे निकल सकते हैं। योजना की सही जानकारी सरकारी वेबसाइट (.gov.in) या नज़दीकी CSC / ब्लॉक कार्यालय से ही लें।",
        explainEn: "Clicking unknown links or installing APK files for welfare schemes (PM Kisan, pension, ration) can compromise your phone and drain your bank account. Verify schemes only through official (.gov.in) websites or local CSC centers.",
        stepsHi: [
          "लिंक या APK फ़ाइल न खोलें और न ही इंस्टॉल करें।",
          "योजना की सही जानकारी के लिए नज़दीकी CSC केंद्र या ब्लॉक कार्यालय जाएं।",
          "अगर कोई ऐप इंस्टॉल हो गया है तो उसे हटा दें और बैंक को बताएं।"
        ],
        stepsEn: [
          "Do not click links and do not install any APK file sent via SMS or WhatsApp.",
          "Verify scheme information only at your nearest CSC center or official .gov.in portal.",
          "If an unknown app was installed, remove it immediately and alert your bank."
        ],
        strong: [
          "pm kisan installment download", "claim government subsidy click"
        ],
        medium: [
          "free laptop", "free mobile", "muft laptop", "muft mobile", "मुफ्त लैपटॉप", "मुफ्त मोबाइल",
          "ration card band", "ration card cancel", "ration card cancelled", "ration card ruk",
          "राशन कार्ड बंद", "राशन कार्ड रद्द", "राशन कार्ड निरस्त",
          "pension band", "pension ruk", "पेंशन बंद", "पेंशन रुक", "पेंशन रुक गई",
          "kist ruk", "किस्त रुक", "yojana ka paisa", "योजना का पैसा", "सरकारी योजना का पैसा", "सरकारी लाभ", "सरकारी सहायता",
          "pm kisan installment", "pm kisan ekyc", "subsidy credited", "government subsidy approved", "free laptop scheme", "free smartphone scheme", "pension suspended"
        ],
        weak: [
          "pm kisan", "pmkisan", "पीएम किसान", "पी एम किसान", "kisan samman nidhi", "किसान सम्मान निधि",
          "ujjwala", "उज्ज्वला", "ayushman", "aayushman", "आयुष्मान",
          "ration card", "राशन कार्ड", "pension", "पेंशन", "yojana", "योजना", "subsidy", "सब्सिडी", "सरकारी लाभ"
        ]
      },

      lottery: {
        nameHi: "लॉटरी / इनाम का झांसा",
        nameEn: "Lottery / Prize / Lucky Draw Scam",
        reasonHi: "इसमें लॉटरी या इनाम जीतने का झांसा दिया गया है",
        reasonEn: "This message falsely claims you won a lottery or lucky draw prize",
        explainHi: "जिस लॉटरी या ड्रॉ में आपने हिस्सा ही नहीं लिया, उसमें इनाम नहीं मिलता। इनाम के लिए 'फ़ीस' या 'टैक्स' माँगा जाए तो वह पक्की ठगी है।",
        explainEn: "You cannot win a lottery or prize you never entered. Demanding advance 'processing fees' or 'tax' to release winnings is a 100% textbook scam.",
        stepsHi: [
          "कोई पैसा न भेजें और दिए गए नंबर पर संपर्क न करें।",
          "मैसेज को डिलीट कर दें।"
        ],
        stepsEn: [
          "Do not send any money and do not contact the phone number provided.",
          "Delete the message and block the sender."
        ],
        strong: [
          "lottery jeet", "lottery jeeti", "lottery jita", "lottery lagi", "lottery nikli",
          "kbc lucky draw", "kbc lottery", "kbc jeet", "lucky draw winner",
          "you have won", "youve won", "you won prize", "you won cash", "you have won lottery", "won lucky draw", "won cash prize", "selected in lucky draw", "congratulations you won",
          "aap jeet gaye", "lakh jeete", "lakh jeet", "laakh jeete", "laakh jeet",
          "आप जीत गए", "आपने जीता", "आपने लॉटरी जीती", "लॉटरी जीती", "लॉटरी जीत", "लॉटरी लगी", "लॉटरी निकली",
          "इनाम जीता", "लाख जीते", "लाख जीत", "लकी ड्रा में जीते", "इनाम पाने के लिए टैक्स"
        ],
        medium: [
          "lottery", "लॉटरी", "lucky draw", "लकी ड्रा", "claim prize", "claim your prize", "claim your winning",
          "prize money", "cash prize", "इनामी राशि", "tax jama", "टैक्स जमा", "इनाम पाने के लिए", "लकी ड्रा विजेता"
        ],
        weak: ["inaam", "इनाम", "congratulations", "बधाई"]
      },

      job_offer: {
        nameHi: "नौकरी / घर बैठे कमाई का झांसा",
        nameEn: "Fake Job / Work-From-Home Scam",
        reasonHi: "इसमें घर बैठे कमाई या नौकरी का लालच दिया गया है",
        reasonEn: "This message offers unrealistic earnings for simple tasks",
        explainHi: "घर बैठे आसानी से रोज़ हज़ारों कमाने का वादा, या नौकरी के लिए रजिस्ट्रेशन फ़ीस माँगना ठगी का आम तरीका है। असली नौकरी देने वाले पहले पैसे नहीं माँगते।",
        explainEn: "Promising thousands of rupees daily for liking videos or asking for advance registration/security fees is fraud. Genuine employers never ask applicants to pay upfront fees.",
        stepsHi: [
          "रजिस्ट्रेशन फ़ीस या सिक्योरिटी के नाम पर पैसे न भेजें।",
          "कंपनी की असली वेबसाइट और पता खुद जाँचें।"
        ],
        stepsEn: [
          "Never pay registration or security fees to secure a job.",
          "Verify the employer on legitimate official company portals and job boards."
        ],
        strong: [
          "ghar baithe kamao", "ghar baithe kamayein", "ghar baithe kamai", "ghar baithe paise",
          "rozana kamao", "roz kamao",
          "earn per day by liking", "earn per day liking", "earn daily by liking", "like videos and earn", "like youtube videos earn",
          "earn money liking videos", "earn 2000 per day", "earn 3000 per day", "earn 5000 per day", "earn 1000 per day", "earn money by liking",
          "ratings on google maps", "ratings on google", "rate on google maps", "per review", "reviews on google", "ratings google maps",
          "घर बैठे कमाएं", "घर बैठे कमाई", "घर बैठे पैसे", "रोज कमाएं", "रोज कमाओ",
          "यूट्यूब वीडियो लाइक करके कमाएं", "वीडियो लाइक करके पैसे", "घर बैठे रोज कमाएं"
        ],
        medium: [
          "work from home", "part time job", "online job", "data entry job", "like karo paise", "video like",
          "liking youtube videos", "liking videos", "like videos", "per day by liking", "subscribe youtube channels earn",
          "joining fee", "registration fee", "registration fees", "naukri pakki", "job guarantee",
          "earn per day", "earn daily", "daily income", "daily earning", "earn from home", "part time job earn", "simple tasks earn money",
          "वर्क फ्रॉम होम", "पार्ट टाइम जॉब", "ऑनलाइन जॉब", "जॉइनिंग फीस", "रजिस्ट्रेशन फीस",
          "नौकरी पक्की", "जॉब गारंटी", "रोज 2000 कमाएं", "रोज 3000 कमाएं", "रोज 5000 कमाएं", "घर बैठे नौकरी"
        ],
        weak: ["job", "jobs", "naukri", "नौकरी", "vacancy", "bharti", "भर्ती"]
      },

      loan: {
        nameHi: "तुरंत लोन का झांसा",
        nameEn: "Instant Loan / No Document Scam",
        reasonHi: "इसमें बिना कागज़ के तुरंत लोन या फ़ीस का झांसा है",
        reasonEn: "This message offers instant loans without documents for an upfront fee",
        explainHi: "बिना कागज़ात के तुरंत लोन का वादा करके पहले 'प्रोसेसिंग फ़ीस' माँगना ठगी है। असली बैंक लोन मंज़ूर करने से पहले पैसे नहीं माँगता। नकली लोन ऐप आपके फ़ोटो और कॉन्टैक्ट भी चुरा सकते हैं।",
        explainEn: "Promising instant loans without documents while demanding an upfront processing fee is a scam. Fake loan apps can also steal your private photos, contacts, and personal data.",
        stepsHi: [
          "कोई फ़ीस न भेजें और अनजान लोन ऐप इंस्टॉल न करें।",
          "लोन के लिए अपने बैंक या किसी जाने-पहचाने वित्तीय संस्थान से ही संपर्क करें।"
        ],
        stepsEn: [
          "Do not transfer advance processing fees and do not install unverified loan apps.",
          "Apply for credit only through recognized banks or RBI-registered lenders."
        ],
        strong: [
          "bina document loan", "bina documents loan", "bina cibil", "loan processing fee",
          "loan approved without documents", "instant loan without documents", "loan without cibil", "pay fee to get loan",
          "badnaam karenge", "contacts ko gandi photos", "contacts ko photo", "gandi photos bhej", "contacts ko gandi",
          "बिना दस्तावेज लोन", "बिना कागज लोन", "बिना सिबिल", "बिना कागजात लोन मंजूर", "बिना सिबिल स्कोर लोन"
        ],
        medium: [
          "instant loan", "turant loan", "loan approved", "loan sanction", "loan sanctioned",
          "pre approved loan", "preapproved loan", "processing fee", "loan offer", "loan app",
          "loan approved pay processing fee", "pre approved loan no documents", "instant personal loan approved", "instant loan approved",
          "तुरंत लोन", "इंस्टेंट लोन", "लोन मंजूर", "लोन अप्रूव", "प्री अप्रूव्ड",
          "प्रोसेसिंग फीस", "लोन ऑफर", "लोन ऐप", "मिनट में लोन", "लोन मंजूर प्रोसेसिंग फीस", "तुरंत पर्सनल लोन", "मिनटों में लोन"
        ],
        weak: ["loan", "लोन"]
      },

      electricity: {
        nameHi: "बिजली कनेक्शन कटने की धमकी",
        nameEn: "Electricity Disconnection Threat",
        reasonHi: "इसमें बिजली कनेक्शन कटने का डर दिखाया गया है",
        reasonEn: "This message threatens that your power supply will be cut tonight",
        explainHi: "बिजली विभाग मैसेज में 'आज रात कनेक्शन कट जाएगा' लिखकर आपसे किसी नंबर पर कॉल करने या लिंक पर क्लिक करने को नहीं कहता। यह ठगों की चाल है।",
        explainEn: "Electricity departments (such as UPPCL) never send SMS messages threatening disconnection tonight while asking you to call a personal phone number. This is a targeted fraud scheme.",
        stepsHi: [
          "दिए गए नंबर पर कॉल न करें और लिंक न खोलें।",
          "अपना बिल बिजली विभाग की आधिकारिक वेबसाइट / ऐप या नज़दीकी बिजली घर पर जाँचें।"
        ],
        stepsEn: [
          "Do not call the personal phone number and do not click the link provided.",
          "Check your bill status on your electricity provider's official portal (e.g. uppcl.org) or visit your local electricity office."
        ],
        strong: [
          "connection kat", "connection kaat", "connection cut", "bijli connection kat",
          "connection will be disconnected", "electricity will be disconnected", "connection disconnect",
          "power will be cut", "power cut tonight", "power supply will be disconnected", "power supply cut",
          "electricity will be cut", "electricity cut tonight", "electricity connection will be disconnected", "power disconnected tonight",
          "कनेक्शन कट", "बिजली कनेक्शन कट", "बिजली का कनेक्शन कट", "बिजली काट दी जाएगी", "बिजली कट जाएगी", "बिजली कनेक्शन काट दिया जाएगा", "आज रात बिजली कट"
        ],
        medium: [
          "kat jayega", "kat jayegi", "kat jaega", "kat jaegi", "kat diya jayega",
          "power will be disconnected", "power disconnection", "electricity disconnected", "power supply disconnected",
          "electricity bill unpaid", "electricity bill pending", "bill unpaid power cut", "power supply stopped",
          "कट जाएगा", "कट जाएगी", "कट जायेगा", "कट जायेगी", "काट दी जाएगी", "काट दिया जाएगा",
          "bijli bill nahi bhara", "bijli bill pending", "bijli bill update", "bijli bill unpaid",
          "बिजली बिल नहीं भरा", "बिजली बिल पेंडिंग", "बिजली बिल अपडेट", "बिजली बिल बकाया", "बिल बकाया है", "बिजली आपूर्ति बंद"
        ],
        weak: ["bijli bill", "बिजली बिल", "electricity bill", "bijli", "बिजली", "bill pending", "बिल पेंडिंग", "power cut", "power bill", "power"]
      },

      authority_threat: {
        nameHi: "पुलिस / CBI / 'डिजिटल अरेस्ट' की धमकी",
        nameEn: "Police / CBI / 'Digital Arrest' Extortion",
        reasonHi: "इसमें पुलिस, CBI या गिरफ्तारी का डर दिखाया गया है",
        reasonEn: "This message threatens police arrest, CBI action, or customs seizure",
        explainHi: "पुलिस, CBI या कोई सरकारी एजेंसी फ़ोन या वीडियो कॉल पर 'डिजिटल अरेस्ट' नहीं करती और न ही पैसे माँगती है। यह डराकर पैसे ऐंठने का तरीका है।",
        explainEn: "Police, CBI, Customs, and court officials NEVER place citizens under 'digital arrest' via phone or video call, nor do they demand money transfers to clear cases. This is criminal extortion.",
        stepsHi: [
          "डरें नहीं। कॉल काट दें और कोई पैसा न भेजें।",
          "किसी भरोसेमंद व्यक्ति या नज़दीकी थाने से सलाह लें।",
          "तुरंत 1930 पर कॉल करके बताएं।"
        ],
        stepsEn: [
          "Do not panic. Disconnect the call and do not transfer any money.",
          "Consult family members or visit your local police station immediately.",
          "Call national cyber helpline 1930 immediately to report the extortion attempt."
        ],
        strong: [
          "digital arrest", "डिजिटल अरेस्ट", "arrest warrant", "अरेस्ट वारंट", "गिरफ्तारी वारंट",
          "digital arrest warrant", "arrest warrant issued", "parcel contains narcotics", "parcel contains drugs", "parcel seized by customs",
          "cbi officer calling", "police officer calling", "customs officer calling", "case registered against you",
          "fir registered against you", "your son had an accident", "son in police custody",
          "cbi se bol", "cbi officer", "सीबीआई", "narcotics", "नारकोटिक्स",
          "drugs parcel", "parcel mein drugs", "parcel me drugs", "money laundering", "मनी लॉन्ड्रिंग",
          "money laundering and pornography", "seized with illegal drugs", "seized with drugs", "parcel containing illegal",
          "trai notice", "trai notice your mobile", "acp cyber crime",
          "aapke naam par case", "aapke naam pe case", "आपके नाम पर केस", "आपके नाम पर मामला",
          "cyber police se bol", "customs se bol", "trai se bol", "ट्राई से बोल",
          "आपके बेटे का एक्सीडेंट", "बेटा पुलिस हिरासत में", "पार्सल में ड्रग्स", "डिजिटल अरेस्ट किया गया"
        ],
        medium: [
          "police case", "पुलिस केस", "legal action", "कानूनी कार्रवाई", "fir darj", "एफआईआर",
          "court notice", "कोर्ट नोटिस", "parcel customs", "customs parcel", "parcel pakda", "parcel seized",
          "customs parcel", "police custody", "son had an accident", "hospital accident send money", "arrested by police", "legal notice issued",
          "पार्सल पकड़ा", "warrant", "वारंट", "थाने में बंद", "अस्पताल में भर्ती तुरंत पैसे", "कानूनी नोटिस"
        ],
        weak: ["arrest", "gireftar", "giraftari", "गिरफ्तार", "police", "पुलिस", "court", "कोर्ट", "customs"]
      }
    },

    // Used when the message looks risky only because of links / urgency / APKs, with no scam type found.
    genericRisk: {
      nameHi: "संदिग्ध लिंक या जल्दबाज़ी",
      nameEn: "Suspicious Links or Urgency",
      explainHi: "इस मैसेज में अनजान लिंक या जल्दबाज़ी करवाने वाली भाषा है। ठग अक्सर ऐसा ही करते हैं।",
      explainEn: "This message contains unverified links or high-pressure urgency language typically associated with cyber fraud.",
      stepsHi: [
        "लिंक पर क्लिक करने से पहले रुकें और भेजने वाले की पहचान खुद जाँचें।",
        "कोई जानकारी या पैसा न भेजें।"
      ],
      stepsEn: [
        "Pause before clicking any links and independently verify the sender's identity.",
        "Do not share any personal information or transfer any money."
      ]
    },

    // ---------------------------------------------------------------------------------
    // Signals that do not depend on a scam type.
    // ---------------------------------------------------------------------------------
    generic: {
      points: { link: 2, shortener: 2, lookalike: 3, apk: 4, phone: 1, urgency: 1.5, action: 1 },
      labelsHi: {
        link: "इसमें एक अनजान लिंक है",
        shortener: "इसमें छोटा (छिपा हुआ) लिंक है",
        lookalike: "लिंक सरकारी या बैंक जैसा दिखता है, पर असली नहीं लगता",
        apk: "इसमें APK फ़ाइल इंस्टॉल करने को कहा गया है",
        phone: "इसमें किसी फ़ोन नंबर पर संपर्क करने को कहा गया है",
        urgency: "जल्दबाज़ी करवाई जा रही है",
        action: "लिंक खोलने या ऐप डाउनलोड करने को कहा गया है"
      },
      labelsEn: {
        link: "Contains an unverified / unknown web link",
        shortener: "Contains a masked short link (e.g. bit.ly, tinyurl)",
        lookalike: "Link mimics an official bank/government domain",
        apk: "Prompts to download or install an APK file",
        phone: "Urges contacting an unverified personal phone number",
        urgency: "Uses artificial time pressure to rush your decision",
        action: "Demands immediate action: clicking links or app download"
      },
      urgency: [
        "urgent", "urgently", "immediately", "turant", "abhi", "jaldi", "aaj hi", "aaj raat",
        "tonight", "today itself", "within 24 hours", "at the earliest", "action required",
        "24 ghante", "24 hours", "last date", "kal tak", "warna", "otherwise", "right now",
        "nahi to", "nahin to",
        "तुरंत", "अभी", "जल्दी", "आज ही", "आज रात", "24 घंटे", "आखिरी तारीख", "अंतिम तारीख",
        "वरना", "नहीं तो"
      ],
      action: [
        "click", "क्लिक", "download", "डाउनलोड", "install", "इंस्टॉल", "tap here",
        "link par", "link pe", "लिंक पर", "लिंक खोलें", "open link", "visit link",
        "verify", "contact on whatsapp", "message on whatsapp", "whatsapp us", "whatsapp par",
        "सत्यापित करें", "व्हाट्सएप पर संपर्क", "व्हाट्सएप पर भेजें"
      ],
      // A link on one of these domains (or a subdomain of them) is NOT penalised. Extend as needed.
      trustedDomains: [
        "gov.in", "nic.in", "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com",
        "paytm.com", "phonepe.com", "amazon.in", "flipkart.com", "irctc.co.in", "npci.org.in",
        "jio.com", "airtel.in", "google.com", "youtube.com", "whatsapp.com", "wa.me",
        "uppcl.org", "upenergy.in", "iocl.com", "indiapost.gov.in", "parivahan.gov.in"
      ],
      shorteners: [
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd", "shorturl.at",
        "tiny.cc", "ow.ly", "t.ly", "bitly.com", "rebrand.ly"
      ],
      // Official-sounding words. A NON-trusted link containing one of these gets the "lookalike" penalty.
      brandWords: [
        "sbi", "kyc", "kisan", "pmkisan", "aadhaar", "aadhar", "uidai", "epfo", "irctc", "gov", "india",
        "paytm", "phonepe", "bijli", "electricity", "upi", "bank", "refund", "loan", "lottery", "kbc",
        "jio", "airtel", "customs", "narcotics", "discom", "fastag", "reward", "yono", "challan"
      ]
    },

    verdicts: {
      scam: {
        colour: "red",
        headlineHi: "ठगी का ख़तरा! इस पर भरोसा न करें।",
        headlineEn: "Scam Warning! Do not trust or reply to this message."
      },
      suspicious: {
        colour: "yellow",
        headlineHi: "सावधान रहें, यह संदिग्ध लगता है।",
        headlineEn: "Caution: This message appears suspicious."
      },
      low_risk: {
        colour: "green",
        headlineHi: "कोई ख़तरे का संकेत नहीं मिला।",
        headlineEn: "No immediate scam indicators found.",
        noteHi: "फिर भी OTP, पिन या पासवर्ड किसी को न बताएं। यह जाँच पूरी तरह पक्की नहीं है।",
        noteEn: "Always stay cautious. Never share OTPs, PINs, or passwords with anyone. This check is an automated helper, not a guarantee.",
        stepsHi: [
          "अनजान लिंक या APK फ़ाइल न खोलें।",
          "OTP, पिन और पासवर्ड किसी को न बताएं।",
          "शक हो तो अपने बैंक या किसी भरोसेमंद व्यक्ति से पूछ लें।"
        ],
        stepsEn: [
          "Do not open unverified links or install APK files.",
          "Never share your OTP, PIN, or password with anyone.",
          "If in doubt, verify directly with your bank or trusted family members."
        ]
      }
    },

    // Shown for scam / suspicious results. VERIFY these are still current before launch.
    helplinesHi: "अगर पैसे कट गए हों तो तुरंत 1930 पर कॉल करें। शिकायत cybercrime.gov.in पर कर सकते हैं। संदिग्ध कॉल या मैसेज की रिपोर्ट के लिए संचार साथी (sancharsaathi.gov.in) का 'चक्षु' इस्तेमाल करें।",
    helplinesEn: "If money was deducted, immediately call National Cyber Crime Helpline 1930. File a complaint at cybercrime.gov.in. Report suspicious calls or messages on Sanchar Saathi's 'Chakshu' portal (sancharsaathi.gov.in)."
  };

  if (typeof module !== "undefined" && module.exports) module.exports = RULES;
  else root.SCAM_RULES = RULES;
})(typeof globalThis !== "undefined" ? globalThis : this);
