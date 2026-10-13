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
    "दें", "दो", "साझा करें", "साझा कीजिए", "दर्ज करें",
    // Bengali (বাংলা)
    "দিন", "বলুন", "পাঠান", "শেয়ার করুন", "লিখুন", "দিন না", "পাঠিয়ে দিন", "প্রদান করুন"
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
      "केवाईसी अपडेट हो गया", "केवाईसी पूरा हो गया",
      // Bengali (বাংলা)
      "কাউকে বলবেন না", "কারও সাথে শেয়ার করবেন না", "কখনও শেয়ার করবেন না", "কাউকে দেবেন না",
      "কাউকে জানাবেন না", "কারো সাথে শেয়ার করবেন না", "কারুর সাথে শেয়ার করবেন না",
      "ব্যাংক কখনও ওটিপি চায় না", "ব্যাংক কখনো ওটিপি চায় না", "ব্যাংক কখনও পাসওয়ার্ড চায় না",
      "ওটিপি কাউকে দেবেন না", "পাসওয়ার্ড কাউকে দেবেন না", "সিভিভি কাউকে দেবেন না",
      "পিন কাউকে দেবেন না", "গোপন তথ্য কাউকে দেবেন না", "কখনই শেয়ার করবেন না",
      "শুধুমাত্র ডেলিভারি পার্টনারকে", "শুধুমাত্র ডেলিভারি বয়কে", "ডেলিভারি পার্টনারকে দিন",
      "ডেলিভারি বয়কে জানান", "ডেলিভারি বয়কে কোড দিন",
      "সফলভাবে জমা হয়েছে", "সফলভাবে সম্পন্ন হয়েছে", "সফলভাবে প্রাপ্ত হয়েছে",
      "বিদ্যুৎ বিল জমা হয়েছে", "বিল জমা হয়েছে", "বিল পরিশোধ হয়েছে", "বিল সফলভাবে জমা হয়েছে",
      "আপনার ব্যাংক অ্যাকাউন্টে জমা হয়েছে", "আপনার একাউন্টে জমা হয়েছে", "টাকা অ্যাকাউন্টে জমা হয়েছে",
      "ভর্তুকি জমা হয়েছে", "ভর্তুকি সফলভাবে জমা হয়েছে",
      "আপনার যাত্রা শুভ হোক", "শুভ যাত্রা",
      "টেলিকম অ্যাডভাইসরি", "মোবাইল সংযোগ বিচ্ছিন্ন করে না", "সিম সংযোগ বিচ্ছিন্ন করে না"
    ],

    // ---------------------------------------------------------------------------------
    // Scam categories. Each has phrases (strong / medium / weak) and the Hindi text shown to the user.
    // ---------------------------------------------------------------------------------
    categories: {

      otp_request: {
        nameHi: "OTP / गुप्त कोड मांगना",
        nameEn: "OTP / Secret Code Request",
        nameBn: "OTP / গোপন কোড চাওয়া",
        reasonHi: "इसमें OTP या गुप्त कोड माँगा जा रहा है",
        reasonEn: "This message asks for an OTP or verification code",
        reasonBn: "এতে OTP বা ভেরিফিকেশন কোড চাওয়া হচ্ছে",
        explainHi: "असली बैंक, सरकारी विभाग या कंपनी आपसे कभी OTP, पिन या गुप्त कोड नहीं मांगती। OTP बताते ही आपके खाते से पैसे निकल सकते हैं।",
        explainEn: "Authentic banks, government portals, and companies never ask for your OTP or verification code. Sharing your OTP can cause immediate unauthorized money withdrawals.",
        explainBn: "প্রকৃত ব্যাংক, সরকারি দপ্তর বা কোম্পানি কখনোই আপনার কাছে OTP, পিন বা গোপন কোড চায় না। OTP দিলেই একাউন্ট থেকে টাকা চুরি হতে পারে।",
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
        stepsBn: [
          "কাউকে OTP, PIN বা CVV দেবেন না, এমনকি সে নিজেকে ব্যাংক কর্মকর্তা বললেও নয়।",
          "ফোন কেটে দিন বা মেসেজের কোনো উত্তর দেবেন না।",
          "যদি ভুল করে OTP দিয়ে থাকেন, তবে অবিলম্বে ১৯৩০ নম্বরে কল করুন।"
        ],
        avoidEn: "Never share your OTP, PIN, password, or CVV with anyone over call, SMS, or WhatsApp.",
        avoidHi: "अभी क्या न करें: किसी भी अनजान कॉल, मैसेज या व्हाट्सएप पर अपना OTP, पिन या CVV कभी न बताएं।",
        avoidBn: "এখন কী করবেন না: ফোন, বার্তা বা হোয়াটসঅ্যাপে কাউকে নিজের OTP, পিন বা CVV কোনোমতেই দেবেন না।",
        verifyEn: "What to verify independently: Check transactions and alert history directly inside your official bank app.",
        verifyHi: "खुद कहाँ जाँचें: बैंक खाते के सही लेन-देन की पुष्टि सीधे अपने आधिकारिक बैंकिंग ऐप से करें।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: ব্যাংক লেনদেনের সত্যতা সরাসরি অফিশিয়াল মোবাইল ব্যাংকিং অ্যাপে পরীক্ষা করুন।",
        reportEn: "Where to report or seek help: For financial cyber fraud in India, immediately call 1930 and report on cybercrime.gov.in.",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: वित्तीय धोखाधड़ी होने पर तुरंत राष्ट्रीय साइबर हेल्पलाइन 1930 पर कॉल करें और cybercrime.gov.in पर रिपोर्ट दर्ज करें।",
        reportBn: "কোথায় रिपोर्ट করবেন বা সাহায্য নেবেন: আর্থিক সাইবার প্রতারণার ক্ষেত্রে অবিলম্বে ১৯৩০ নম্বরে কল করুন এবং cybercrime.gov.in-এ অভিযোগ জানান।",
        strong: ask(["otp", "ओटीपी", "ওটিপি", "verification code", "digit code", "सत्यापन कोड", "ভেরিফিকেশন কোড", "সিক্রেট কোড"]).concat([
          "share your otp", "enter the otp", "provide the otp", "enter otp to receive", "enter otp to get",
          "ओटीपी शेयर", "ओटीपी किसी को", "ओटीपी दर्ज करें", "ओटीपी दर्ज करो", "ओटीपी बताइए", "ओटीपी बताएं",
          "ওটিপি শেয়ার", "ওটিপি কাউকে", "ওটিপি লিখুন", "ওটিপি দিন", "ওটিপি বলুন", "ওটিপি পাঠান"
        ]),
        medium: [],
        weak: []
      },

      info_request: {
        nameHi: "निजी जानकारी मांगना",
        nameEn: "Personal / Financial Details Request",
        nameBn: "ব্যক্তিগত / আর্থিক তথ্য চাওয়া",
        reasonHi: "इसमें पिन, पासवर्ड या निजी जानकारी माँगी जा रही है",
        reasonEn: "This message asks for your PIN, password, or sensitive details",
        reasonBn: "এতে পিন, পাসওয়ার্ড বা গোপন আর্থিক তথ্য চাওয়া হচ্ছে",
        explainHi: "आधार, पैन, कार्ड नंबर, पासवर्ड या पिन जैसी जानकारी मैसेज या फ़ोन पर माँगना ठगी का आम तरीका है। इससे आपके नाम पर धोखाधड़ी हो सकती है।",
        explainEn: "Asking for Aadhaar, PAN, card numbers, passwords, or PINs over message or call is a major sign of fraud. Scammers use this for identity theft and unauthorized debits.",
        explainBn: "আধার, প্যান, এটিএম কার্ড নম্বর, পাসওয়ার্ড বা পিন চাওয়া প্রতারণার লক্ষণ। প্রতারকরা এর মাধ্যমে পরিচয় চুরি ও টাকা হাতানোর চেষ্টা করে।",
        stepsHi: [
          "अनजान व्यक्ति को आधार, पैन, कार्ड या बैंक की जानकारी न दें।",
          "बैंक से बात करनी हो तो कार्ड के पीछे लिखे असली नंबर पर खुद कॉल करें।"
        ],
        stepsEn: [
          "Never disclose Aadhaar, PAN, debit/credit card, or bank account details to unverified contacts.",
          "To contact your bank, call only the official phone number printed on the back of your card."
        ],
        stepsBn: [
          "অপরিচিত কাউকে আধার, প্যান বা ব্যাংকের তথ্য দেবেন না।",
          "কার্ডের পেছনে থাকা অফিশিয়াল হেল্পলাইন নম্বরে যোগাযোগ করুন।"
        ],
        avoidEn: "Do NOT share your PIN, password, card details, or Aadhaar number over calls or messages.",
        avoidHi: "अभी क्या न करें: किसी भी अनजान कॉल या मैसेज पर अपना पिन, पासवर्ड, कार्ड विवरण या आधार नंबर न दें।",
        avoidBn: "এখন কী করবেন না: কোনো বার্তা বা ফোনে নিজের পিন, পাসওয়ার্ড, কার্ড বিবরণ বা আধার নম্বর দেবেন না।",
        verifyEn: "What to verify independently: Contact your bank branch directly using the verified customer care number on your card.",
        verifyHi: "खुद कहाँ जाँचें: केवल अपने बैंक कार्ड के पीछे मुद्रित असली कस्टमर केयर नंबर पर कॉल करके पुष्टि करें।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: আপনার ব্যাংক কার্ডের পেছনে থাকা অনুমোদিত কাস্টমার কেয়ার নম্বরে নিজে ফোন করে যাচাই করুন।",
        reportEn: "Where to report or seek help: Report unauthorized identity theft attempts immediately at 1930 and cybercrime.gov.in.",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: डेटा चोरी या धोखाधड़ी की तुरंत शिकायत 1930 और cybercrime.gov.in पर दर्ज कराएं।",
        reportBn: "কোথায় रिपोर्ट করবেন বা সাহায্য নেবেন: তথ্য চুরি বা প্রতারণার চেষ্টা অবিলম্বে ১৯৩০ ও cybercrime.gov.in-এ রিপোর্ট করুন।",
        strong: ask(["upi pin", "atm pin", "card pin", "debit card pin", "credit card pin", "cvv", "password", "netbanking password",
                     "पासवर्ड", "यूपीआई पिन", "एटीएम पिन", "सीवीवी", "upi पिन", "atm पिन",
                     "ইউপিআই পিন", "এটিএম পিন", "পাসওয়ার্ড", "সিভিভি"]).concat([
          "enter upi pin", "enter your upi pin", "enter atm pin", "enter password", "provide your pin", "provide your password",
          "कार्ड का सीवीवी", "पिन दर्ज करें", "पासवर्ड दर्ज करें", "यूपीआई पिन डालें",
          "কার্ডের সিভিভি", "পিন লিখুন", "পাসওয়ার্ড দিন", "ইউপিআই পিন দিন", "পিন বলুন"
        ]),
        medium: ask(["aadhaar number", "aadhar number", "adhar number", "aadhaar no", "aadhar no",
                     "pan number", "pan no", "card number", "bank details", "bank detail", "account number", "credit card number", "card details",
                     "आधार नंबर", "पैन नंबर", "कार्ड नंबर", "बैंक डिटेल", "बैंक डिटेल्स", "खाता नंबर", "अकाउंट नंबर", "खाता विवरण", "बैंक खाता विवरण", "कार्ड विवरण",
                     "আধার নম্বর", "প্যান নম্বর", "কার্ড নম্বর", "ব্যাংক বিবরণ", "অ্যাকাউন্ট নম্বর"]).concat([
          "verify on whatsapp", "verify your aadhaar on whatsapp", "verify aadhaar on whatsapp", "aadhaar verification on whatsapp",
          "व्हाट्सएप पर सत्यापित", "व्हाट्सएप पर वेरीफाई", "হোয়াটসঅ্যাপে যাচাই", "হোয়াটসঅ্যাপে ভেরিফাই"
        ]),
        weak: []
      },

      sim_kyc: {
        nameHi: "सिम बंद / KYC अपडेट की धमकी",
        nameEn: "SIM Block / Fake KYC Threat",
        nameBn: "সিম বন্ধ / KYC আপডেটের হুমকি",
        reasonHi: "इसमें सिम बंद होने या KYC अपडेट का डर दिखाया गया है",
        reasonEn: "This message threatens that your SIM or KYC will be blocked",
        reasonBn: "এতে সিম কার্ড বা কেওয়াইসি বন্ধ করার ভয় দেখানো হয়েছে",
        explainHi: "ठग डराते हैं कि आपका सिम या खाता बंद हो जाएगा, ताकि आप जल्दबाज़ी में उनकी बात मानें। KYC के नाम पर आए अनजान लिंक या कॉल पर कोई जानकारी न दें।",
        explainEn: "Scammers create panic by claiming your SIM or account will be suspended today to force you into acting hurriedly. Never click unknown links or call unverified numbers for KYC.",
        explainBn: "প্রতারকরা ভয় দেখায় যে আপনার সিম বা অ্যাকাউন্ট বন্ধ হয়ে যাবে। কেওয়াইসির নামে আসা লিঙ্কে তথ্য দেবেন না।",
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
        stepsBn: [
          "মেসেজে আসা লিঙ্কে ক্লিক করবেন না এবং দেওয়া নম্বরে কল করবেন না।",
          "কেওয়াইসির প্রয়োজনে সরাসরি ব্যাংকের শাখায় বা টেলিকম স্টোরে যান।"
        ],
        avoidEn: "Do NOT click the link, do NOT call the provided mobile number, and do NOT install any remote support apps.",
        avoidHi: "अभी क्या न करें: दिए गए लिंक पर क्लिक न करें, उस नंबर पर कॉल न करें और कोई रिमोट ऐप इंस्टॉल न करें।",
        avoidBn: "এখন কী করবেন না: প্রদত্ত লিঙ্কে ক্লিক করবেন না, ওই নম্বরে কল করবেন না এবং কোনো দূরবর্তী অ্যাপ ইনস্টল করবেন না।",
        verifyEn: "What to verify independently: Visit an authorized telecom store or official bank branch to check your KYC status.",
        verifyHi: "खुद कहाँ जाँचें: अपनी टेलीकॉम कंपनी के अधिकृत स्टोर या बैंक शाखा में खुद जाकर KYC स्थिति जाँचें।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: আপনার টেলিকম অপারেটরের অনুমোদিত স্টোর বা ব্যাংকের শাখায় গিয়ে কেওয়াইসি স্ট্যাটাস যাচাই করুন।",
        reportEn: "Where to report or seek help: Report fake disconnection threats on Sanchar Saathi Chakshu (sancharsaathi.gov.in) and call 1930.",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: फर्जी सिम ब्लॉक की शिकायत संचार साथी 'चक्षु' (sancharsaathi.gov.in) पर करें और 1930 पर कॉल करें।",
        reportBn: "কোথায় রিপোর্ট করবেন বা সাহায্য নেবেন: ভুয়ো সংযোগ বিচ্ছিন্নের অভিযোগ সঞ্চার সাথীর 'চক্ষু' (sancharsaathi.gov.in) পোর্টালে করুন এবং ১৯৩০-এ জানান।",
        strong: [
          "sim block", "sim blocked", "sim band", "sim deactivate", "sim deactivated", "sim kat", "sim cut",
          "sim will be blocked", "sim card will be blocked", "sim will be deactivated", "sim suspended", "sim will be suspended",
          "सिम बंद", "सिम ब्लॉक", "सिम कट", "सिम डिएक्टिवेट", "सिम बंद हो जाएगा", "सिम ब्लॉक हो जाएगा", "सिम कार्ड बंद",
          "সিম বন্ধ", "সিম ব্লক", "সিম বন্ধ হয়ে যাবে", "সিম ব্লক হয়ে যাবে", "সিম কার্ড বন্ধ", "সিম ডিঅ্যাক্টিভেট"
        ],
        medium: [
          "kyc update", "kyc expire", "kyc expired", "kyc pending", "kyc verify", "kyc verification",
          "kyc nahi", "e kyc update", "number band ho", "number block ho", "sim verification", "sim verification pending",
          "update kyc immediately", "complete your kyc", "complete kyc", "kyc verification pending", "update your aadhaar",
          "aadhaar suspicious activity", "suspicious activity verify", "verify on whatsapp",
          "केवाईसी अपडेट", "केवाईसी एक्सपायर", "केवाईसी पेंडिंग", "केवाईसी वेरिफिकेशन", "केवाईसी नहीं",
          "नंबर बंद हो", "नंबर ब्लॉक हो", "केवाईसी तुरंत करें", "केवाईसी सत्यापन", "केवाईसी अधूरा", "आधार अपडेट करें", "सिम वेरिफिकेशन",
          "কেওয়াইসি আপডেট", "কেওয়াইসি বাকি", "কেওয়াইসি যাচাই", "কেওয়াইসি পেন্ডিং", "আধার আপডেট করুন", "নম্বর বন্ধ হয়ে যাবে", "সিম ভেরিফিকেশন"
        ],
        weak: ["kyc", "केवाईसी", "sim", "सिम", "কেওয়াইসি"]
      },

      bank_threat: {
        nameHi: "बैंक खाता / कार्ड बंद होने की धमकी",
        nameEn: "Bank Account / Card Suspension Threat",
        nameBn: "ব্যাংক অ্যাকাউন্ট / কার্ড বন্ধের হুমকি",
        reasonHi: "इसमें खाता, कार्ड या पैन बंद होने का डर दिखाया गया है",
        reasonEn: "This message threatens that your account, card, or PAN is blocked",
        reasonBn: "এতে অ্যাকাউন্ট, কার্ড বা প্যান বন্ধ করার ভয় দেখানো হয়েছে",
        explainHi: "खाता, ATM कार्ड या पैन बंद होने का डर दिखाकर जानकारी माँगना ठगी है। बैंक ऐसे मैसेज या कॉल पर जानकारी नहीं मांगता।",
        explainEn: "Using fear of account suspension or PAN deactivation to extract confidential credentials is fraud. Legitimate banks never ask for sensitive data via SMS or call.",
        explainBn: "অ্যাকাউন্ট বা এটিএম কার্ড বন্ধের ভয় দেখিয়ে গোপন তথ্য হাতিয়ে নেওয়া প্রতারণা। ব্যাংক কখনো মেসেজে প্যান বা কার্ড বিবরণ চায় না।",
        stepsHi: [
          "लिंक न खोलें और कोई जानकारी न दें।",
          "अपने बैंक की शाखा जाएं या कार्ड के पीछे लिखे असली नंबर पर खुद कॉल करें।"
        ],
        stepsEn: [
          "Do not open the link and do not provide any confidential information.",
          "Visit your bank branch directly or call the official phone number on the back of your card."
        ],
        stepsBn: [
          "লিঙ্ক খুলবেন না এবং কোনো ব্যাংকিং তথ্য দেবেন না।",
          "সরাসরি আপনার ব্যাংক শাখায় যান বা কার্ডের পেছনের আসল নম্বরে যোগাযোগ করুন।"
        ],
        avoidEn: "Do NOT open the link, do NOT enter PAN/Aadhaar/NetBanking credentials, and never install update APKs.",
        avoidHi: "अभी क्या न करें: लिंक न खोलें, पैन या नेटबैंकिंग पासवर्ड न डालें और कोई अपडेट APK इंस्टॉल न करें।",
        avoidBn: "এখন কী করবেন না: লিঙ্ক খুলবেন না, প্যান বা নেট ব্যাংকিং পাসওয়ার্ড দেবেন না এবং কোনো আপডেট APK ইনস্টল করবেন না।",
        verifyEn: "What to verify independently: Login only through the official verified bank app or visit your home branch in person.",
        verifyHi: "खुद कहाँ जाँचें: केवल बैंक के आधिकारिक सत्यापित ऐप पर लॉग इन करें या सीधे अपनी बैंक शाखा जाएं।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: শুধুমাত্র ব্যাংকের নিজস্ব অফিশিয়াল অ্যাপে লগইন করুন বা সরাসরি নিজের ব্যাংক শাখায় যান।",
        reportEn: "Where to report or seek help: If money was deducted, immediately call 1930 and report to your bank's fraud desk.",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: यदि पैसे कट गए हों, तो तुरंत 1930 पर कॉल करें और बैंक के फ्रॉड हेल्पडेस्क को सूचित करें।",
        reportBn: "কোথায় রিপোর্ট করবেন বা সাহায্য নেবেন: টাকা কেটে নেওয়া হলে অবিলম্বে ১৯৩০-এ কল করুন এবং ব্যাংকের ফ্রড হেল্পডেস্কে জানান।",
        strong: [
          "account block", "account blocked", "account freeze", "account frozen", "account band",
          "account suspend", "account suspended", "account will be blocked", "account will be suspended", "account will be deactivated",
          "खाता बंद", "खाता ब्लॉक", "खाता फ्रीज", "अकाउंट बंद", "अकाउंट ब्लॉक", "अकाउंट फ्रीज", "खाता बंद हो जाएगा", "अकाउंट बंद हो जाएगा",
          "atm card block", "atm card blocked", "atm card band", "debit card block", "debit card blocked",
          "card band ho", "card block ho", "pan card block", "pan card blocked", "pan band", "card will be blocked",
          "पैन कार्ड ब्लॉक", "पैन कार्ड बंद", "एटीएम कार्ड बंद", "एटीएम कार्ड ब्लॉक", "पैन कार्ड बंद हो जाएगा", "खाता ब्लॉक कर दिया गया", "खाता फ्रीज कर दिया",
          "reward points worth", "reward points expiring", "reward points expire", "redeem reward points", "redeem points directly", "redeem points as cash",
          "fastag has been blacklisted", "fastag blacklisted", "fastag blocked", "update your fastag", "fastag kyc",
          "yono account is blocked", "sbi yono", "yono netbanking",
          "অ্যাকাউন্ট ব্লক", "অ্যাকাউন্ট বন্ধ", "একাউন্ট ব্লক", "একাউন্ট বন্ধ", "অ্যাকাউন্ট ফ্রিজ", "একাউন্ট বন্ধ হয়ে যাবে", "প্যান কার্ড ব্লক", "প্যান কার্ড বন্ধ", "এটিএম কার্ড ব্লক", "রিওয়ার্ড পয়েন্ট", "ফাস্ট্যাগ ব্লক", "ফাস্ট্যাগ ব্ল্যাকলিস্ট"
        ],
        medium: [
          "account closed", "account close", "pan update", "pan expire", "pan expired", "pan suspended", "pan card suspended",
          "update pan card", "link pan with account", "pan not linked", "pan aadhaar link", "unauthorized transaction",
          "bank se bol", "bank se call", "bank manager bol", "bank officer",
          "बैंक से बोल", "बैंक मैनेजर", "बैंक अधिकारी", "पैन अपडेट", "पैन कार्ड लिंक", "पैन लिंक करें", "खाता चालू रखने के लिए", "अकाउंट चालू रखने के लिए",
          "প্যান আপডেট", "প্যান কার্ড লিংক", "প্যান লিংক করুন", "ব্যাংক থেকে বলছি", "ব্যাংক ম্যানেজার বলছি", "ব্যাংক কর্মকর্তা", "অ্যাকাউন্ট সচল রাখার জন্য"
        ],
        weak: ["se bol raha", "se bol rahi", "se bol rha", "से बोल रहा", "से बोल रही", "bank account", "बैंक खाता", "ব্যাংক অ্যাকাউন্ট", "ব্যাংক একাউন্ট"]
      },

      upi_refund: {
        nameHi: "UPI / QR कोड / रिफ़ंड का झांसा",
        nameEn: "UPI / Mistaken Transfer / QR Scam",
        nameBn: "UPI / ভুয়ো রিফান্ড / কিউআর কোড ফাঁদ",
        reasonHi: "इसमें पैसे पाने के नाम पर पिन, QR कोड या रिक्वेस्ट का झांसा है",
        reasonEn: "This message uses fake money refunds, QR codes, or mistaken transfers as bait",
        reasonBn: "এতে টাকা পাওয়ার নামে পিন বা কিউআর কোড স্ক্যান করার ফাঁদ রয়েছে",
        explainHi: "पैसे पाने के लिए कभी पिन डालने या QR कोड स्कैन करने की ज़रूरत नहीं होती। पिन डालने पर पैसे आपके खाते से कटते हैं, आते नहीं।",
        explainEn: "You NEVER need to enter your UPI PIN or scan a QR code to receive money. Entering your PIN always deducts money from your account, it never credits money.",
        explainBn: "টাকা পাওয়ার জন্য কখনো ইউপিআই পিন দিতে হয় না বা কিউআর কোড স্ক্যান করতে হয় না। পিন দিলে আপনার অ্যাকাউন্ট থেকেই টাকা কেটে নেওয়া হয়।",
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
        stepsBn: [
          "টাকা পাওয়ার জন্য কখনো ইউপিআই পিন দেবেন না বা কিউআর কোড স্ক্যান করবেন না।",
          "টাকা কেটে নেওয়া হলে অবিলম্বে ১৯৩০ নম্বরে কল করুন।"
        ],
        avoidEn: "NEVER enter your UPI PIN or scan a QR code to receive money. Reject unknown collect requests.",
        avoidHi: "अभी क्या न करें: पैसे पाने के लिए कभी UPI पिन न डालें और न ही QR कोड स्कैन करें। अनजान पेमेंट रिक्वेस्ट Reject करें।",
        avoidBn: "এখন কী করবেন না: টাকা পাওয়ার জন্য কখনো ইউপিআই পিন (UPI PIN) দেবেন না বা কিউআর কোড স্ক্যান করবেন না।",
        verifyEn: "What to verify independently: Check your bank balance directly inside your UPI app without following unverified instructions.",
        verifyHi: "खुद कहाँ जाँचें: किसी के कहने पर नहीं, सीधे अपने UPI ऐप की पासबुक में जाकर बैंक बैलेंस खुद देखें।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: কারো কথামতো নয়, সরাসরি আপনার নিজস্ব ইউপিআই অ্যাপের পাসবুকে গিয়ে ব্যালেন্স যাচাই করুন।",
        reportEn: "Where to report or seek help: Immediately call 1930 to freeze fraudulent UPI transactions and report on cybercrime.gov.in.",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: धोखाधड़ी होते ही तुरंत 1930 पर कॉल करें ताकि गलत ट्रांसफर फ्रीज कराया जा सके।",
        reportBn: "কোথায় रिपोर्ट করবেন বা সাহায্য নেবেন: আর্থিক প্রতারণা হলে অবিলম্বে ১৯৩০ নম্বরে কল করুন যাতে লেনদেন ফ্রিজ করা যায়।",
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
          "गलती से ट्रांसफर वापस", "गलती से पैसे वापस", "गलती से भेज दिया वापस", "गलती से ट्रांसफर हो गए",
          "টাকা পেতে পিন", "টাকা পাওয়ার জন্য পিন দিন", "পিন দিলেই টাকা পাবেন", "কিউআর কোড স্ক্যান করে টাকা", "টাকা ফেরত পেতে পিন", "টাকা পাওয়ার জন্য কিউআর স্ক্যান"
        ],
        medium: [
          "qr code scan", "qr scan", "scan qr", "scan karke paise", "scan karein paise",
          "galti se paise", "galti se transfer", "galti se bhej", "wrong transfer",
          "request accept", "request approve", "collect request",
          "paisa wapas kar", "paise wapas kar", "paise wapas kardo", "refund link", "refund pin", "refund claim",
          "sent by mistake", "transferred by mistake", "money sent by mistake", "receive money enter pin",
          "click to receive refund", "refund approved",
          "क्यूआर कोड स्कैन", "क्यूआर स्कैन", "गलती से पैसे", "गलती से ट्रांसफर",
          "रिक्वेस्ट एक्सेप्ट", "रिक्वेस्ट अप्रूव", "पैसे वापस कर", "पैसे वापस कर दो", "पैसे वापस कर दीजिए", "पैसे वापस करें",
          "কিউআর কোড স্ক্যান", "কিউআর স্ক্যান", "ভুল করে টাকা", "ভুল করে পাঠিয়ে ফেলেছি", "টাকা ফেরত দিন", "টাকা ফেরত পাঠান", "রিফান্ড লিংক"
        ],
        weak: ["refund", "रिफंड", "cashback", "कैशबैक", "রিফান্ড", "ক্যাশব্যাক"]
      },

      govt_scheme: {
        nameHi: "सरकारी योजना के नाम पर ठगी",
        nameEn: "Fake Government Scheme / Subsidy Scam",
        nameBn: "ভুয়ো সরকারি প্রকল্প / অনুদানের প্রলোভন",
        reasonHi: "इसमें सरकारी योजना या सब्सिडी के नाम पर लालच या डर दिखाया गया है",
        reasonEn: "This message uses government welfare schemes or subsidies as bait",
        reasonBn: "এতে সরকারি যোজনা বা অনুদানের নামে প্রলোভন বা প্রতারণা রয়েছে",
        explainHi: "योजनाओं के नाम पर आए अनजान लिंक या APK फ़ाइल खोलने से आपका फ़ोन हैक हो सकता है और बैंक खाते से पैसे निकल सकते हैं। योजना की सही जानकारी सरकारी वेबसाइट (.gov.in) या नज़दीकी CSC / ब्लॉक कार्यालय से ही लें।",
        explainEn: "Clicking unknown links or installing APK files for welfare schemes (PM Kisan, pension, ration) can compromise your phone and drain your bank account. Verify schemes only through official (.gov.in) websites or local CSC centers.",
        explainBn: "সরকারি প্রকল্পের নামে আসা অপরিচিত লিঙ্ক বা APK ফাইল খুললে মোবাইল হ্যাক হতে পারে। প্রকল্পের সঠিক তথ্য কেবল সরকারি পোর্টাল (.gov.in) থেকে নিন।",
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
        stepsBn: [
          "কোনো অজানা লিঙ্ক বা APK ফাইল খুলবেন না এবং ডাউনলোড করবেন না।",
          "প্রকল্পের সঠিক তথ্যের জন্য নিকটস্থ বাংলা সহায়তা কেন্দ্র (BSK), CSC বা সরকারি অফিসে যোগাযোগ করুন।",
          "যদি কোনো অ্যাপ ইনস্টল হয়ে থাকে তবে অবিলম্বে তা মুছে দিন এবং ব্যাংককে জানান।"
        ],
        avoidEn: "Do NOT pay registration fees and never install APK files sent via SMS or messaging apps.",
        avoidHi: "अभी क्या न करें: किसी भी योजना के लिए रजिस्ट्रेशन शुल्क न दें और न ही कोई APK फ़ाइल डाउनलोड करें।",
        avoidBn: "এখন কী করবেন না: কোনো প্রকল্পের জন্য অগ্রিম রেজিস্ট্রেশন ফি দেবেন না এবং কোনো APK ফাইল ডাউনলোড করবেন না।",
        verifyEn: "What to verify independently: Verify welfare scheme benefits only on official government portals ending in .gov.in or at local CSC/BSK centers.",
        verifyHi: "खुद कहाँ जाँचें: सरकारी योजनाओं की पात्रता केवल आधिकारिक .gov.in वेबसाइट या नज़दीकी CSC केंद्र से सत्यापित करें।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: প্রকল্পের সঠিক তথ্য ও সুবিধা কেবল অফিশিয়াল .gov.in ওয়েবসাইট বা স্থানীয় বাংলা সহায়তা কেন্দ্রে যাচাই করুন।",
        reportEn: "Where to report or seek help: Report fake government portals or phishing SMS on Chakshu (sancharsaathi.gov.in) and 1930.",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: फर्जी सरकारी पोर्टल या मैसेज की सूचना संचार साथी के 'चक्षु' और 1930 पर दें।",
        reportBn: "কোথায় রিপোর্ট করবেন বা সাহায্য নেবেন: ভুয়ো সরকারি ওয়েবসাইটের রিপোর্ট 'চক্ষু' (sancharsaathi.gov.in) ও ১৯৩০-এ জানান।",
        strong: [
          "pm kisan installment download", "claim government subsidy click",
          "পিএম কিষাণ কিস্তি ডাউনলোড", "সরকারি ভর্তুকি পেতে ক্লিক"
        ],
        medium: [
          "free laptop", "free mobile", "muft laptop", "muft mobile", "मुफ्त लैपटॉप", "मुफ्त मोबाइल",
          "ration card band", "ration card cancel", "ration card cancelled", "ration card ruk",
          "राशन कार्ड बंद", "राशन कार्ड रद्द", "राशन कार्ड निरस्त",
          "pension band", "pension ruk", "पेंशन बंद", "पेंशन रुक", "पेंशन रुक गई",
          "kist ruk", "किस्त रुक", "yojana ka paisa", "योजना का पैसा", "सरकारी योजना का पैसा", "सरकारी लाभ", "सरकारी सहायता",
          "pm kisan installment", "pm kisan ekyc", "subsidy credited", "government subsidy approved", "free laptop scheme", "free smartphone scheme", "pension suspended",
          "ফ্রি ল্যাপটপ", "ফ্রি মোবাইল", "রেশন কার্ড বাতিল", "রেশন কার্ড বন্ধ", "পেনশন বন্ধ", "যোজনার টাকা", "সরকারি সাহায্য", "লক্ষ্মীর ভাণ্ডার", "কৃষক বন্ধু", "প্রধানমন্ত্রী আবাস যোজনা"
        ],
        weak: [
          "pm kisan", "pmkisan", "पीएम किसान", "पी एम किसान", "kisan samman nidhi", "किसान सम्मान निधि",
          "ujjwala", "उज्ज्वला", "ayushman", "aayushman", "आयुष्मान",
          "ration card", "राशन कार्ड", "pension", "पेंशन", "yojana", "योजना", "subsidy", "सब्सिडी", "सरकारी लाभ",
          "পিএম কিষাণ", "উজ্জ্বলা", "আয়ুষ্মান", "রেশন কার্ড", "পেনশন", "যোজনা", "ভর্তুকি", "সরকারি লাভ"
        ]
      },

      lottery: {
        nameHi: "लॉटरी / इनाम का झांसा",
        nameEn: "Lottery / Prize / Lucky Draw Scam",
        nameBn: "লটারি / পুরস্কারের মিথ্যা প্রলোভন",
        reasonHi: "इसमें लॉटरी या इनाम जीतने का झांसा दिया गया है",
        reasonEn: "This message falsely claims you won a lottery or lucky draw prize",
        reasonBn: "এতে লটারি বা পুরস্কার জেতার মিথ্যা দাবি করা হয়েছে",
        explainHi: "जिस लॉटरी या ड्रॉ में आपने हिस्सा ही नहीं लिया, उसमें इनाम नहीं मिलता। इनाम के लिए 'फ़ीस' या 'टैक्स' माँगा जाए तो वह पक्की ठगी है।",
        explainEn: "You cannot win a lottery or prize you never entered. Demanding advance 'processing fees' or 'tax' to release winnings is a 100% textbook scam.",
        explainBn: "যে লটারিতে আপনি অংশ নেননি, তাতে পুরস্কার পাওয়া যায় না। পুরস্কার দেওয়ার নাম করে অগ্রিম 'ফি' বা 'ট্যাক্স' চাওয়া ১০০% প্রতারণা।",
        stepsHi: [
          "कोई पैसा न भेजें और दिए गए नंबर पर संपर्क न करें।",
          "मैसेज को डिलीट कर दें।"
        ],
        stepsEn: [
          "Do not send any money and do not contact the phone number provided.",
          "Delete the message and block the sender."
        ],
        stepsBn: [
          "কোনো টাকা পাঠাবেন না এবং প্রদত্ত নম্বরে যোগাযোগ করবেন না।",
          "মেসেজটি মুছে দিন এবং প্রেরককে ব্লক করুন।"
        ],
        avoidEn: "Do NOT pay advance processing fees, taxes, or GST to claim any lottery prize.",
        avoidHi: "अभी क्या न करें: किसी भी लॉटरी या इनाम के लिए 'टैक्स' या 'प्रोसेसिंग फ़ीस' के नाम पर कोई पैसा न भेजें।",
        avoidBn: "এখন কী করবেন না: কোনো লটারি বা পুরস্কারের নাম করে ট্যাক্স বা প্রসেসিং ফি হিসেবে কোনো টাকা পাঠাবেন না।",
        verifyEn: "What to verify independently: Recognize that genuine companies or TV shows never demand money via WhatsApp/SMS to release prizes.",
        verifyHi: "खुद कहाँ जाँचें: समझें कि कोई भी असली कंपनी या टीवी शो इनाम देने के नाम पर पहले पैसे कभी नहीं माँगता।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: মনে রাখবেন কোনো আসল কোম্পানি বা টিভি শো পুরস্কার দেওয়ার জন্য আগে টাকা চায় না।",
        reportEn: "Where to report or seek help: Report the lottery scam caller or message to Chakshu (sancharsaathi.gov.in) and 1930.",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: फर्जी लॉटरी कॉल या मैसेज की रिपोर्ट संचार साथी 'चक्षु' और 1930 पर करें।",
        reportBn: "কোথায় রিপোর্ট করবেন বা সাহায্য নেবেন: ভুয়ো লটারি মেসেজের অভিযোগ সঞ্চার সাথী 'চক্ষু' এবং ১৯৩০ নম্বরে দায়ের করুন।",
        strong: [
          "lottery jeet", "lottery jeeti", "lottery jita", "lottery lagi", "lottery nikli",
          "kbc lucky draw", "kbc lottery", "kbc jeet", "lucky draw winner",
          "you have won", "youve won", "you won prize", "you won cash", "you have won lottery", "won lucky draw", "won cash prize", "selected in lucky draw", "congratulations you won",
          "aap jeet gaye", "lakh jeete", "lakh jeet", "laakh jeete", "laakh jeet",
          "आप जीत गए", "आपने जीता", "आपने लॉटरी जीती", "लॉटरी जीती", "लॉटरी जीत", "लॉटरी लगी", "लॉटरी निकली",
          "इनाम जीता", "लाख जीते", "लाख जीत", "लकी ड्रा में जीते", "इनाम पाने के लिए टैक्स",
          "লটারি জিতেছেন", "আপনি জিতেছেন", "পুরস্কার জিতেছেন", "লাকি ড্র বিজয়ী", "কেবিসি লটারি", "ইনাম পেয়েছেন", "লটারি পেয়েছেন"
        ],
        medium: [
          "lottery", "लॉटरी", "lucky draw", "लकी ड्रा", "claim prize", "claim your prize", "claim your winning",
          "prize money", "cash prize", "इनामी राशि", "tax jama", "टैक्स जमा", "इनाम पाने के लिए", "लकी ड्रा विजेता",
          "লটারি", "লাকি ড্র", "পুরস্কারের টাকা", "ট্যাক্স জমা দিন", "লটারি পেতে ট্যাক্স"
        ],
        weak: ["inaam", "इनाम", "congratulations", "बधाई", "পুরস্কার", "অভিনন্দন"]
      },

      job_offer: {
        nameHi: "नौकरी / घर बैठे कमाई का झांसा",
        nameEn: "Fake Job / Work-From-Home Scam",
        nameBn: "চাকরি / ঘরে বসে আয়ের মিথ্যা প্রলোভন",
        reasonHi: "इसमें घर बैठे कमाई या नौकरी का लालच दिया गया है",
        reasonEn: "This message offers unrealistic earnings for simple tasks",
        reasonBn: "এতে ঘরে বসে কাজের নামে অস্বাভাবিক আয়ের মিথ্যা লোভ দেখানো হয়েছে",
        explainHi: "घर बैठे आसानी से रोज़ हज़ारों कमाने का वादा, या नौकरी के लिए रजिस्ट्रेशन फ़ीस माँगना ठगी का आम तरीका है। असली नौकरी देने वाले पहले पैसे नहीं माँगते।",
        explainEn: "Promising thousands of rupees daily for liking videos or asking for advance registration/security fees is fraud. Genuine employers never ask applicants to pay upfront fees.",
        explainBn: "ঘরে বসে ভিডিও লাইক করে বা সহজ কাজের জন্য হাজার হাজার টাকা দেওয়ার প্রতিশ্রুতি এবং চাকরির জন্য রেজিস্ট্রেশন ফি চাওয়া সম্পূর্ণ প্রতারণা। আসল কোনো কোম্পানি চাকরি দেওয়ার জন্য আগে টাকা চায় না।",
        stepsHi: [
          "रजिस्ट्रेशन फ़ीस या सिक्योरिटी के नाम पर पैसे न भेजें।",
          "कंपनी की असली वेबसाइट और पता खुद जाँचें।"
        ],
        stepsEn: [
          "Never pay registration or security fees to secure a job.",
          "Verify the employer on legitimate official company portals and job boards."
        ],
        stepsBn: [
          "রেজিস্ট্রেশন ফি বা জামানতের নামে কোনো টাকা পাঠাবেন না।",
          "কোম্পানির অফিশিয়াল ওয়েবসাইট ও সত্যতা নিজে যাচাই করুন।"
        ],
        avoidEn: "Do NOT pay registration fees, security deposits, or advance money for job offers.",
        avoidHi: "अभी क्या न करें: नौकरी के लिए कोई रजिस्ट्रेशन शुल्क, सिक्योरिटी डिपॉजिट या अग्रिम पैसे न भेजें।",
        avoidBn: "এখন কী করবেন না: চাকরির জন্য কোনো রেজিস্ট্রেশন ফি, জামানত বা অগ্রিম টাকা পাঠাবেন না।",
        verifyEn: "What to verify independently: Verify the hiring company on its official verified careers portal or LinkedIn, never through Telegram/WhatsApp.",
        verifyHi: "खुद कहाँ जाँचें: नौकरी की पेशकश केवल कंपनी के आधिकारिक करियर पोर्टल पर जाँचें, टेलीग्राम या व्हाट्सएप पर भरोसा न करें।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: চাকরির প্রস্তাব কেবল কোম্পানির অফিশিয়াল ক্যারিয়ার পোর্টালে যাচাই করুন, টেলিগ্রাম বা হোয়াটসঅ্যাপে নয়।",
        reportEn: "Where to report or seek help: Report fake job schemes and telegram task fraud to 1930 and cybercrime.gov.in.",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: फर्जी नौकरी और टास्क फ्रॉड की शिकायत 1930 और cybercrime.gov.in पर करें।",
        reportBn: "কোথায় রিপোর্ট করবেন বা সাহায্য নেবেন: ভুয়ো চাকরি বা টাস্ক প্রতারণার অভিযোগ ১৯৩০ এবং cybercrime.gov.in-এ জানান।",
        strong: [
          "ghar baithe kamao", "ghar baithe kamayein", "ghar baithe kamai", "ghar baithe paise",
          "rozana kamao", "roz kamao",
          "earn per day by liking", "earn per day liking", "earn daily by liking", "like videos and earn", "like youtube videos earn",
          "earn money liking videos", "earn 2000 per day", "earn 3000 per day", "earn 5000 per day", "earn 1000 per day", "earn money by liking",
          "ratings on google maps", "ratings on google", "rate on google maps", "per review", "reviews on google", "ratings google maps",
          "घर बैठे कमाएं", "घर बैठे कमाई", "घर बैठे पैसे", "रोज कमाएं", "रोज कमाओ",
          "यूट्यूब वीडियो लाइक करके कमाएं", "वीडियो लाइक करके पैसे", "घर बैठे रोज कमाएं",
          "ঘরে বসে আয়", "ঘরে বসে রোজগার", "ঘরে বসে টাকা", "প্রতিদিন আয়", "ভিডিও লাইক করে আয়", "ইউটিউব ভিডিও লাইক", "সহজ কাজ করে টাকা"
        ],
        medium: [
          "work from home", "part time job", "online job", "data entry job", "like karo paise", "video like",
          "liking youtube videos", "liking videos", "like videos", "per day by liking", "subscribe youtube channels earn",
          "joining fee", "registration fee", "registration fees", "naukri pakki", "job guarantee",
          "earn per day", "earn daily", "daily income", "daily earning", "earn from home", "part time job earn", "simple tasks earn money",
          "वर्क फ्रॉम होम", "पार्ट टाइम जॉब", "ऑनलाइन जॉब", "जॉइनिंग फीस", "रजिस्ट्रेशन फीस",
          "नौकरी पक्की", "जॉब गारंटी", "रोज 2000 कमाएं", "रोज 3000 कमाएं", "रोज 5000 कमाएं", "घर बैठे नौकरी",
          "ওয়ার্ক ফ্রম হোম", "পার্ট টাইম কাজ", "পার্ট টাইম জব", "অনলাইন কাজ", "অনলাইন জব", "রেজিস্ট্রেশন ফি", "জব গ্যারান্টি"
        ],
        weak: ["job", "jobs", "naukri", "नौकरी", "vacancy", "bharti", "भर्ती", "চাকরি", "নিয়োগ"]
      },

      loan: {
        nameHi: "तुरंत लोन का झांसा",
        nameEn: "Instant Loan / No Document Scam",
        nameBn: "তাত্ক্ষণিক ঋণের ভুয়ো প্রলোভন",
        reasonHi: "इसमें बिना कागज़ के तुरंत लोन या फ़ीस का झांसा है",
        reasonEn: "This message offers instant loans without documents for an upfront fee",
        reasonBn: "এতে নথিপত্র ছাড়াই অবিলম্বে লোন দেওয়ার নামে ফি চাওয়া হয়েছে",
        explainHi: "बिना कागज़ात के तुरंत लोन का वादा करके पहले 'प्रोसेसिंग फ़ीस' माँगना ठगी है। असली बैंक लोन मंज़ूर करने से पहले पैसे नहीं माँगता। नकली लोन ऐप आपके फ़ोटो और कॉन्टैक्ट भी चुरा सकते हैं।",
        explainEn: "Promising instant loans without documents while demanding an upfront processing fee is a scam. Fake loan apps can also steal your private photos, contacts, and personal data.",
        explainBn: "নথিপত্র ছাড়া অবিলম্বে লোন দেওয়ার প্রতিশ্রুতি দিয়ে প্রসেসিং ফি চাওয়া সম্পূর্ণ প্রতারণা। আসল ব্যাংক ঋণ মঞ্জুর করার আগে টাকা চায় না। ভুয়ো লোন অ্যাপ ব্যক্তিগত ছবি ও কনট্যাক্ট চুরি করতে পারে।",
        stepsHi: [
          "कोई फ़ीस न भेजें और अनजान लोन ऐप इंस्टॉल न करें।",
          "लोन के लिए अपने बैंक या किसी जाने-पहचाने वित्तीय संस्थान से ही संपर्क करें।"
        ],
        stepsEn: [
          "Do not transfer advance processing fees and do not install unverified loan apps.",
          "Apply for credit only through recognized banks or RBI-registered lenders."
        ],
        stepsBn: [
          "কোনো প্রসেসিং ফি পাঠাবেন না এবং অচেনা লোন অ্যাপ ইনস্টল করবেন না।",
          "ঋণের জন্য কেবল নিবন্ধিত ব্যাংক বা আরবিআই অনুমোদিত সংস্থার সাথে যোগাযোগ করুন।"
        ],
        avoidEn: "Do NOT pay advance processing fees and do NOT download unknown loan APK apps.",
        avoidHi: "अभी क्या न करें: लोन के लिए अग्रिम प्रोसेसिंग फ़ीस न दें और अनजान लोन APK डाउनलोड न करें।",
        avoidBn: "এখন কী করবেন না: ঋণের জন্য অগ্রিম প্রসেসিং ফি দেবেন না এবং অচেনা লোন APK অ্যাপ ডাউনলোড করবেন না।",
        verifyEn: "What to verify independently: Check if the lender is registered with the Reserve Bank of India (RBI) via rbi.org.in or official branch.",
        verifyHi: "खुद कहाँ जाँचें: पुष्टि करें कि ऋणदाता RBI द्वारा पंजीकृत बैंक या NBFC है, केवल आधिकारिक शाखा से बात करें।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: ঋণদাতা সংস্থাটি আরবিআই (RBI) অনুমোদিত ব্যাংক বা এনবিএফসি কি না তা সরাসরি অফিশিয়াল শাখায় বা rbi.org.in-এ যাচাই করুন।",
        reportEn: "Where to report or seek help: Report predatory illegal loan apps and extortion to 1930 and Chakshu (sancharsaathi.gov.in).",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: अवैध लोन ऐप और धमकी देने वालों की शिकायत 1930 और संचार साथी के 'चक्षु' पर करें।",
        reportBn: "কোথায় রিপোর্ট করবেন বা সাহায্য নেবেন: বেআইনি লোন অ্যাপ ও হয়রানির অভিযোগ ১৯৩০ এবং সঞ্চার সাথীর 'চক্ষু' পোর্টালে জানান।",
        strong: [
          "bina document loan", "bina documents loan", "bina cibil", "loan processing fee",
          "loan approved without documents", "instant loan without documents", "loan without cibil", "pay fee to get loan",
          "badnaam karenge", "contacts ko gandi photos", "contacts ko photo", "gandi photos bhej", "contacts ko gandi",
          "बिना दस्तावेज लोन", "बिना कागज लोन", "बिना सिबिल", "बिना कागजात लोन मंजूर", "बिना सिबिल स्कोर लोन",
          "কাগজপত্র ছাড়া লোন", "নথিপত্র ছাড়া লোন", "সিভিল ছাড়া লোন", "বিনা নথিপত্রে ঋণ", "লোন প্রসেসিং ফি"
        ],
        medium: [
          "instant loan", "turant loan", "loan approved", "loan sanction", "loan sanctioned",
          "pre approved loan", "preapproved loan", "processing fee", "loan offer", "loan app",
          "loan approved pay processing fee", "pre approved loan no documents", "instant personal loan approved", "instant loan approved",
          "तुरंत लोन", "इंस्टेंट लोन", "लोन मंजूर", "लोन अप्रूव", "प्री अप्रूव्ड",
          "प्रोसेसिंग फीस", "लोन ऑफर", "लोन ऐप", "मिनट में लोन", "लोन मंजूर प्रोसेसिंग फीस", "तुरंत पर्सनल लोन", "मिनटों में लोन",
          "তাত্ক্ষণিক ঋণ", "তাত্ক্ষণিক লোন", "ইনস্ট্যান্ট লোন", "লোন মঞ্জুর", "লোন অফার", "লোন অ্যাপ", "প্রসেসিং ফি"
        ],
        weak: ["loan", "लोन", "লোন", "ঋণ"]
      },

      electricity: {
        nameHi: "बिजली कनेक्शन कटने की धमकी",
        nameEn: "Electricity Disconnection Threat",
        nameBn: "বিদ্যুৎ সংযোগ বিচ্ছিন্ন করার হুমকি",
        reasonHi: "इसमें बिजली कनेक्शन कटने का डर दिखाया गया है",
        reasonEn: "This message threatens that your power supply will be cut tonight",
        reasonBn: "এতে আজ রাতে বিদ্যুৎ সংযোগ কেটে দেওয়ার ভয় দেখানো হয়েছে",
        explainHi: "बिजली विभाग मैसेज में 'आज रात कनेक्शन कट जाएगा' लिखकर आपसे किसी नंबर पर कॉल करने या लिंक पर क्लिक करने को नहीं कहता। यह ठगों की चाल है।",
        explainEn: "Electricity departments (such as UPPCL) never send SMS messages threatening disconnection tonight while asking you to call a personal phone number. This is a targeted fraud scheme.",
        explainBn: "বিদ্যুৎ বিভাগ কখনো মেসেজ পাঠিয়ে 'আজ রাতে লাইন কেটে দেওয়া হবে' বলে কোনো ব্যক্তিগত নম্বরে ফোন করতে বলে না। এটি প্রতারকদের টাকা হাতিয়ে নেওয়ার কৌশল।",
        stepsHi: [
          "दिए गए नंबर पर कॉल न करें और लिंक न खोलें।",
          "अपना बिल बिजली विभाग की आधिकारिक वेबसाइट / ऐप या नज़दीकी बिजली घर पर जाँचें।"
        ],
        stepsEn: [
          "Do not call the personal phone number and do not click the link provided.",
          "Check your bill status on your electricity provider's official portal (e.g. uppcl.org) or visit your local electricity office."
        ],
        stepsBn: [
          "দেওয়া নম্বরে কল করবেন না এবং কোনো লিঙ্কে ক্লিক করবেন না।",
          "বিদ্যুৎ বিলের সঠিক তথ্য আপনার বিদ্যুৎ পর্ষদের অফিশিয়াল অ্যাপ বা অফিসে গিয়ে জানুন।"
        ],
        avoidEn: "Do NOT call the personal phone number in the SMS and do NOT open the link.",
        avoidHi: "अभी क्या न करें: मैसेज में दिए गए व्यक्तिगत मोबाइल नंबर पर कॉल न करें और लिंक न खोलें।",
        avoidBn: "এখন কী করবেন না: মেসেজে থাকা ব্যক্তিগত মোবাইল নম্বরে কল করবেন না এবং কোনো লিঙ্ক খুলবেন না।",
        verifyEn: "What to verify independently: Check your power bill directly on the state electricity DISCOM portal or at your local sub-station.",
        verifyHi: "खुद कहाँ जाँचें: अपने बिजली बिल की स्थिति बिजली विभाग (DISCOM) के आधिकारिक पोर्टल या स्थानीय बिजली घर पर खुद जाँचें।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: আপনার বিদ্যুৎ বিলের স্থিতি সরাসরি বিদ্যুৎ পর্ষদের অফিশিয়াল পোর্টালে বা স্থানীয় বিদ্যুৎ অফিসে গিয়ে যাচাই করুন।",
        reportEn: "Where to report or seek help: Report fake disconnection messages to Chakshu (sancharsaathi.gov.in) and call 1930 if defrauded.",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: फर्जी बिजली मैसेज की शिकायत संचार साथी 'चक्षु' पर दर्ज करें और पैसे कटने पर 1930 पर तुरंत कॉल करें।",
        reportBn: "কোথায় রিপোর্ট করবেন বা সাহায্য নেবেন: ভুয়ো বিদ্যুৎ বার্তার অভিযোগ সঞ্চার সাথীর 'চক্ষু' (sancharsaathi.gov.in) পোর্টালে করুন এবং ১৯৩০-এ জানান।",
        strong: [
          "connection kat", "connection kaat", "connection cut", "bijli connection kat",
          "connection will be disconnected", "electricity will be disconnected", "connection disconnect",
          "power will be cut", "power cut tonight", "power supply will be disconnected", "power supply cut",
          "electricity will be cut", "electricity cut tonight", "electricity connection will be disconnected", "power disconnected tonight",
          "कनेक्शन कट", "बिजली कनेक्शन कट", "बिजली का कनेक्शन कट", "बिजली काट दी जाएगी", "बिजली कट जाएगी", "बिजली कनेक्शन काट दिया जाएगा", "आज रात बिजली कट",
          "বিদ্যুৎ সংযোগ বিচ্ছিন্ন", "আজ রাতে বিদ্যুৎ বিচ্ছিন্ন", "বিদ্যুৎ লাইন কাটা হবে", "লাইন কেটে দেওয়া হবে", "বিদ্যুৎ সংযোগ কেটে দেওয়া হবে", "আজ রাতে বিদ্যুৎ কাটা হবে"
        ],
        medium: [
          "kat jayega", "kat jayegi", "kat jaega", "kat jaegi", "kat diya jayega",
          "power will be disconnected", "power disconnection", "electricity disconnected", "power supply disconnected",
          "electricity bill unpaid", "electricity bill pending", "bill unpaid power cut", "power supply stopped",
          "कट जाएगा", "कट जाएगी", "कट जायेगा", "कट जायेगी", "काट दी जाएगी", "काट दिया जाएगा",
          "bijli bill nahi bhara", "bijli bill pending", "bijli bill update", "bijli bill unpaid",
          "बिजली बिल नहीं भरा", "बिजली बिल पेंडिंग", "बिजली बिल अपडेट", "बिजली बिल बकाया", "बिल बकाया है", "बिजली आपूर्ति बंद",
          "বিদ্যুৎ বিল বকেয়া", "বিল বাকি আছে", "লাইন কাটা যাবে", "বিদ্যুৎ সরবরাহ বন্ধ"
        ],
        weak: ["bijli bill", "बिजली बिल", "electricity bill", "bijli", "बिजली", "bill pending", "बिल पेंडिंग", "power cut", "power bill", "power", "বিদ্যুৎ বিল", "বিদ্যুৎ", "কারেন্ট বিল"]
      },

      authority_threat: {
        nameHi: "पुलिस / CBI / 'डिजिटल अरेस्ट' की धमकी",
        nameEn: "Police / CBI / 'Digital Arrest' Extortion",
        nameBn: "পুলিশ / সিবিআই / 'ডিজিটাল অ্যারেস্ট' হুমকি",
        reasonHi: "इसमें पुलिस, CBI या गिरफ्तारी का डर दिखाया गया है",
        reasonEn: "This message threatens police arrest, CBI action, or customs seizure",
        reasonBn: "এতে পুলিশ, সিবিআই বা গ্রেফতারের ভয় দেখিয়ে ব্ল্যাকমেল করা হয়েছে",
        explainHi: "पुलिस, CBI या कोई सरकारी एजेंसी फ़ोन या वीडियो कॉल पर 'डिजिटल अरेस्ट' नहीं करती और न ही पैसे माँगती है। यह डराकर पैसे ऐंठने का तरीका है।",
        explainEn: "Police, CBI, Customs, and court officials NEVER place citizens under 'digital arrest' via phone or video call, nor do they demand money transfers to clear cases. This is criminal extortion.",
        explainBn: "পুলিশ, সিবিআই বা কোনো সরকারি সংস্থা কখনো ফোন বা ভিডিও কলে 'ডিজিটাল অ্যারেস্ট' করে না এবং কোনো ব্যাংক অ্যাকাউন্টে টাকা পাঠাতে বলে না। এটি ডাহা চাঁদাবাজি ও প্রতারণা।",
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
        stepsBn: [
          "আতঙ্কিত হবেন না। ফোন কেটে দিন এবং কোনো টাকা পাঠাবেন না।",
          "পরিবারের সদস্য বা নিকটস্থ থানায় অবিলম্বে যোগাযোগ করুন।",
          "অবিলম্বে ১৯৩০ নম্বরে কল করে জানান।"
        ],
        avoidEn: "Do NOT panic, do NOT transfer any money to safe/clearing accounts, and disconnect video calls immediately.",
        avoidHi: "अभी क्या न करें: डरें नहीं, तथाकथित 'सुरक्षित खाते' में पैसे ट्रांसफर न करें और तुरंत वीडियो कॉल काट दें।",
        avoidBn: "এখন কী করবেন না: আতঙ্কিত হবেন না, কোনো 'নিরাপদ অ্যাকাউন্টে' টাকা পাঠাবেন না এবং অবিলম্বে ভিডিও কল কেটে দিন।",
        verifyEn: "What to verify independently: Walk directly into your local police station to verify any alleged legal notice or warrant.",
        verifyHi: "खुद कहाँ जाँचें: किसी भी कथित वारंट या कानूनी नोटिस की पुष्टि के लिए सीधे अपने स्थानीय पुलिस थाने जाएं।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: কোনো নোটিশ বা গ্রেফতারি পরোয়ানার সত্যতা যাচাই করতে সরাসরি নিকটস্থ থানায় যান।",
        reportEn: "Where to report or seek help: For digital arrest or cyber extortion in India, promptly call 1930 and report at cybercrime.gov.in.",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: डिजिटल अरेस्ट या जबरन वसूली की शिकायत तुरंत 1930 पर कॉल करके cybercrime.gov.in पर दर्ज कराएं।",
        reportBn: "কোথায় রিপোর্ট করবেন বা সাহায্য নেবেন: ডিজিটাল অ্যারেস্ট বা তোলাবাজির অভিযোগ জানাতে অবিলম্বে ১৯৩০ নম্বরে কল করুন এবং cybercrime.gov.in-এ অভিযোগ জানান।",
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
          "आपके बेटे का एक्सीडेंट", "बेटा पुलिस हिरासत में", "पार्सल में ड्रग्स", "डिजिटल अरेस्ट किया गया",
          "ডিজিটাল অ্যারেস্ট", "গ্রেফতারি পরোয়ানা", "সিবিআই অফিসার", "পুলিশ অফিসার", "কাস্টমস অফিসার", "পার্সেল ড্রাগস", "পার্সেলে নিষিদ্ধ ওষুধ", "মানি লন্ডারিং", "আপনার নামে মামলা", "ডিজিটাল অ্যারেস্ট পরোয়ানা"
        ],
        medium: [
          "police case", "पुलिस केस", "legal action", "कानूनी कार्रवाई", "fir darj", "एफआईआर",
          "court notice", "कोर्ट नोटिस", "parcel customs", "customs parcel", "parcel pakda", "parcel seized",
          "customs parcel", "police custody", "son had an accident", "hospital accident send money", "arrested by police", "legal notice issued",
          "पार्सल पकड़ा", "warrant", "वारंट", "थाने में बंद", "अस्पताल में भर्ती तुरंत पैसे", "कानूनी नोटिस",
          "পুলিশ কেস", "আইনি পদক্ষেপ", "এফআইআর", "কোর্ট নোটিশ", "কাস্টমস পার্সেল", "ওয়ারেন্ট", "আইনি নোটিশ"
        ],
        weak: ["arrest", "gireftar", "giraftari", "गिरफ्तार", "police", "पुलिस", "court", "कोर्ट", "customs", "গ্রেফতার", "পুলিশ", "কোর্ট", "আদালত", "কাস্টমস"]
      }
    },

    // Used when the message looks risky only because of links / urgency / APKs, with no scam type found.
    genericRisk: {
      nameHi: "संदिग्ध लिंक या जल्दबाज़ी",
      nameEn: "Suspicious Links or Urgency",
      nameBn: "সন্দেহজনক লিঙ্ক বা কৃত্রিম তাড়াহুড়ো",
      explainHi: "इस मैसेज में अनजान लिंक या जल्दबाज़ी करवाने वाली भाषा है। ठग अक्सर ऐसा ही करते हैं।",
      explainEn: "This message contains unverified links or high-pressure urgency language typically associated with cyber fraud.",
      explainBn: "এই মেসেজে অপরিচিত লিঙ্ক বা সিদ্ধান্ত নিতে বাধ্য করার জন্য কৃত্রিম তাড়াহুড়ো রয়েছে। সাইবার প্রতারকরা এই কৌশল ব্যবহার করে।",
      stepsHi: [
        "लिंक पर क्लिक करने से पहले रुकें और भेजने वाले की पहचान खुद जाँचें।",
        "कोई जानकारी या पैसा न भेजें।"
      ],
      stepsEn: [
        "Pause before clicking any links and independently verify the sender's identity.",
        "Do not share any personal information or transfer any money."
      ],
      stepsBn: [
        "লিঙ্কে ক্লিক করার আগে প্রেরকের পরিচয় যাচাই করুন।",
        "কোনো ব্যক্তিগত তথ্য বা টাকা পাঠাবেন না।"
      ],
      avoidEn: "Do NOT click the links and do not share any confidential credentials.",
      avoidHi: "अभी क्या न करें: किसी भी लिंक पर क्लिक न करें और कोई गोपनीय जानकारी न दें।",
      avoidBn: "এখন কী করবেন না: কোনো লিঙ্কে ক্লিক করবেন না এবং কোনো গোপন তথ্য দেবেন না।",
      verifyEn: "What to verify independently: Check the sender's identity through official public directories or direct contact.",
      verifyHi: "खुद कहाँ जाँचें: भेजने वाले की पहचान आधिकारिक माध्यमों से खुद सत्यापित करें।",
      verifyBn: "নিজে কোথায় যাচাই করবেন: প্রেরকের সত্যতা অফিশিয়াল পাবলিক ডিরেক্টরি বা সরাসরি যাচাই করুন।",
      reportEn: "Where to report or seek help: Report suspicious links on Chakshu (sancharsaathi.gov.in) and call 1930 if compromised.",
      reportHi: "कहाँ रिपोर्ट करें या मदद लें: संदिग्ध लिंक की सूचना संचार साथी 'चक्षु' पर दें और नुकसान होने पर 1930 पर संपर्क करें।",
      reportBn: "কোথায় রিপোর্ট করবেন বা সাহায্য নেবেন: সন্দেহজনক লিঙ্কের অভিযোগ সঞ্চার সাথীর 'চক্ষু' এবং ১৯৩০ নম্বরে জানান।"
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
      labelsBn: {
        link: "এতে একটি অচেনা লিঙ্ক রয়েছে",
        shortener: "এতে গোপন করা সংক্ষিপ্ত লিঙ্ক (যেমন bit.ly) রয়েছে",
        lookalike: "লিঙ্কটি ব্যাংক বা সরকারি ওয়েবসাইটের মতো দেখতে কিন্তু আসল নয়",
        apk: "এতে বিপজ্জনক APK ফাইল ইনস্টল করতে বলা হয়েছে",
        phone: "এতে কোনো ব্যক্তিগত মোবাইল নম্বরে যোগাযোগ করতে বলা হয়েছে",
        urgency: "তাড়াহুড়ো করার জন্য কৃত্রিম চাপ সৃষ্টি করা হয়েছে",
        action: "তাৎক্ষণিক লিঙ্ক খোলা বা অ্যাপ ইনস্টল করার নির্দেশ রয়েছে"
      },
      urgency: [
        "urgent", "urgently", "immediately", "turant", "abhi", "jaldi", "aaj hi", "aaj raat",
        "tonight", "today itself", "within 24 hours", "at the earliest", "action required",
        "24 ghante", "24 hours", "last date", "kal tak", "warna", "otherwise", "right now",
        "nahi to", "nahin to",
        "तुरंत", "अभी", "जल्दी", "आज ही", "आज रात", "24 घंटे", "आखिरी तारीख", "अंतिम तारीख",
        "वरना", "नहीं तो",
        "জরুরি", "অবিলম্বে", "আজই", "আজ রাতে", "২৪ ঘণ্টার মধ্যে", "নইলে", "নতুবা", "তাড়াতাড়ি"
      ],
      action: [
        "click", "क्लिक", "download", "डाउनलोड", "install", "इंस्टॉल", "tap here",
        "link par", "link pe", "लिंक पर", "लिंक खोलें", "open link", "visit link",
        "verify", "contact on whatsapp", "message on whatsapp", "whatsapp us", "whatsapp par",
        "सत्यापित करें", "व्हाट्सएप पर संपर्क", "व्हाट्सएप पर भेजें",
        "ক্লিক করুন", "ক্লিক", "ডাউনলোড করুন", "ডাউনলোড", "ইনস্টল করুন", "ইনস্টল", "লিঙ্ক খুলুন", "হোয়াটসঅ্যাপে যোগাযোগ", "হোয়াটসঅ্যাপে পাঠান"
      ],
      // A link on one of these domains (or a subdomain of them) is NOT penalised. Extend as needed.
      trustedDomains: [
        "gov.in", "nic.in", "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com",
        "paytm.com", "phonepe.com", "amazon.in", "flipkart.com", "irctc.co.in", "npci.org.in",
        "jio.com", "airtel.in", "google.com", "youtube.com", "whatsapp.com", "wa.me",
        "uppcl.org", "upenergy.in", "wbsedcl.in", "cesc.co.in", "iocl.com", "indiapost.gov.in", "parivahan.gov.in", "epfindia.gov.in"
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
        headlineEn: "Scam Warning! Do not trust or reply to this message.",
        headlineBn: "প্রতারণার উচ্চ ঝুঁকি! এই মেসেজে বিশ্বাস বা সাড়া দেবেন না।",
        avoidEn: "What to avoid right now: Do NOT click links, do NOT share OTP/PIN/passwords, and do NOT transfer money.",
        avoidHi: "अभी क्या न करें: किसी भी लिंक पर क्लिक न करें, OTP/पिन न बताएं और कोई पैसा न भेजें।",
        avoidBn: "এখন কী করবেন না: কোনো লিঙ্কে ক্লিক করবেন না, ওটিপি/পিন জানাবেন না এবং কোনো টাকা পাঠাবেন না।",
        verifyEn: "What to verify independently: Contact the organization directly via its verified official website or physical branch.",
        verifyHi: "खुद कहाँ जाँचें: संबंधित संस्था से केवल उनकी आधिकारिक वेबसाइट या शाखा में सीधे संपर्क करके पुष्टि करें।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: সংশ্লিষ্ট প্রতিষ্ঠান বা ব্যাংকের অনুমোদিত হেল্পলাইনে নিজে সরাসরি যোগাযোগ করুন।",
        reportEn: "Where to report or seek help: For financial cyber fraud in India, call 1930 promptly and report on cybercrime.gov.in.",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: वित्तीय साइबर धोखाधड़ी होने पर तुरंत 1930 पर कॉल करें और cybercrime.gov.in पर रिपोर्ट करें।",
        reportBn: "কোথায় রিপোর্ট করবেন বা সাহায্য নেবেন: ভারতে আর্থিক সাইবার প্রতারণার ক্ষেত্রে অবিলম্বে ১৯৩০ নম্বরে কল করুন এবং cybercrime.gov.in-এ অভিযোগ জানান।"
      },
      suspicious: {
        colour: "yellow",
        headlineHi: "सावधान रहें, यह संदिग्ध लगता है।",
        headlineEn: "Caution: This message appears suspicious.",
        headlineBn: "সতর্ক থাকুন, এটি সন্দেহজনক মনে হচ্ছে।",
        avoidEn: "What to avoid right now: Do NOT act in a hurry, do NOT click unverified links, and do NOT install remote apps.",
        avoidHi: "अभी क्या न करें: जल्दबाज़ी में कोई कदम न उठाएं, अनजान लिंक न खोलें और कोई ऐप इंस्टॉल न करें।",
        avoidBn: "এখন কী করবেন না: তাড়াহুড়ো করবেন না, অজানা লিঙ্ক খুলবেন না এবং কোনো দূরবর্তী অ্যাপ ইনস্টল করবেন না।",
        verifyEn: "What to verify independently: Log into your official banking or service app independently without using message links.",
        verifyHi: "खुद कहाँ जाँचें: मैसेज के लिंक का उपयोग किए बिना अपने आधिकारिक ऐप में स्वतंत्र रूप से लॉग इन करके स्थिति देखें।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: মেসেজের লিঙ্ক ব্যবহার না করে আপনার অফিশিয়াল অ্যাপ বা পোর্টালে সরাসরি লগইন করে যাচাই করুন।",
        reportEn: "Where to report or seek help: Report suspicious SMS/calls on Sanchar Saathi Chakshu (sancharsaathi.gov.in) or call 1930.",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: संदिग्ध मैसेज की शिकायत संचार साथी 'चक्षु' (sancharsaathi.gov.in) पर करें या 1930 पर पूछें।",
        reportBn: "কোথায় রিপোর্ট করবেন বা সাহায্য নেবেন: সন্দেহজনক বার্তা সঞ্চার সাথীর 'চক্ষু' (sancharsaathi.gov.in) পোর্টালে জানান বা ১৯৩০ নম্বরে যোগাযোগ করুন।"
      },
      low_risk: {
        colour: "green",
        headlineHi: "कोई ख़तरे का संकेत नहीं मिला।",
        headlineEn: "No immediate scam indicators found.",
        headlineBn: "কোনো সরাসরি প্রতারণার লক্ষণ পাওয়া যায়নি।",
        noteHi: "फिर भी OTP, पिन या पासवर्ड किसी को न बताएं। यह जाँच पूरी तरह पक्की नहीं है।",
        noteEn: "Always stay cautious. Never share OTPs, PINs, or passwords with anyone. This check is an automated helper, not a guarantee.",
        noteBn: "তা সত্ত্বেও ওটিপি, পিন বা পাসওয়ার্ড কাউকে বলবেন না। এই স্বয়ংক্রিয় ফলাফল কোনো নিশ্চয়তা নয়।",
        stepsHi: [
          "अनजान लिंक या APK फ़ाइल न खोलें।",
          "OTP, पिन और पासवर्ड किसी को न बताएं।",
          "शक हो तो अपने बैंक या किसी भरोसेमंद व्यक्ति से पूछ लें।"
        ],
        stepsEn: [
          "Do not open unverified links or install APK files.",
          "Never share your OTP, PIN, or password with anyone.",
          "If in doubt, verify directly with your bank or trusted family members."
        ],
        stepsBn: [
          "অপরিচিত লিঙ্ক বা APK ফাইল খুলবেন না।",
          "ওটিপি, পিন ও পাসওয়ার্ড কখনো কাউকে জানাবেন না।",
          "সন্দেহ হলে নিজের ব্যাংক বা পরিবারের সাথে কথা বলুন।"
        ],
        avoidEn: "What to avoid right now: Never share your OTP, PIN, card CVV, or passwords even if requested later.",
        avoidHi: "अभी क्या न करें: बाद में भी कभी किसी को अपना OTP, पिन, CVV या पासवर्ड न बताएं।",
        avoidBn: "এখন কী করবেন না: পরবর্তীতেও কখনোই কাউকে নিজের ওটিপি, পিন, সিভিভি বা পাসওয়ার্ড দেবেন না।",
        verifyEn: "What to verify independently: Check your actual bank statements or order history inside the official app.",
        verifyHi: "खुद कहाँ जाँचें: अपने खाते का लेन-देन या ऑर्डर का विवरण केवल आधिकारिक ऐप के भीतर देखें।",
        verifyBn: "নিজে কোথায় যাচাই করবেন: লেনদেন বা আদেশের বিবরণ কেবল অফিশিয়াল অ্যাপের ভেতর স্টেটমেন্টে দেখুন।",
        reportEn: "Where to report or seek help: For any cybersecurity assistance in India, reach out to helpline 1930 or cybercrime.gov.in.",
        reportHi: "कहाँ रिपोर्ट करें या मदद लें: साइबर सुरक्षा में किसी भी सहायता के लिए राष्ट्रीय हेल्पलाइन 1930 या cybercrime.gov.in से जुड़ें।",
        reportBn: "কোথায় রিপোর্ট করবেন বা সাহায্য নেবেন: সাইবার নিরাপত্তা সংক্রান্ত যেকোনো সাহায্যে জাতীয় হেল্পলাইন ১৯৩০ বা cybercrime.gov.in-এর সাহায্য নিন।"
      }
    },

    // Shown for scam / suspicious results. VERIFY these are still current before launch.
    helplinesHi: "अगर पैसे कट गए हों तो तुरंत 1930 पर कॉल करें। शिकायत cybercrime.gov.in पर कर सकते हैं। संदिग्ध कॉल या मैसेज की रिपोर्ट के लिए संचार साथी (sancharsaathi.gov.in) का 'चक्षु' इस्तेमाल करें।",
    helplinesEn: "If money was deducted, immediately call National Cyber Crime Helpline 1930. File a complaint at cybercrime.gov.in. Report suspicious calls or messages on Sanchar Saathi's 'Chakshu' portal (sancharsaathi.gov.in).",
    helplinesBn: "টাকা খোয়া গেলে অবিলম্বে জাতীয় সাইবার হেল্পলাইন ১৯৩০ নম্বরে কল করুন। cybercrime.gov.in-এ অভিযোগ দায়ের করুন। সন্দেহজনক মেসেজ বা কলের অভিযোগ সঞ্চার সাথীর 'চক্ষু' পোর্টালে (sancharsaathi.gov.in) জানান।"
  };

  if (typeof module !== "undefined" && module.exports) module.exports = RULES;
  else root.SCAM_RULES = RULES;
})(typeof globalThis !== "undefined" ? globalThis : this);
