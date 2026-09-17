/* =========================================================
   ClueWell Mail
   Rule-Based Email Phishing, Spam & Legitimate Analyzer
   ========================================================= */

/* =========================================================
   DOM ELEMENTS
   ========================================================= */

const form = document.getElementById("analyzer-form");

const senderInput = document.getElementById("sender-email");
const subjectInput = document.getElementById("email-subject");
const bodyInput = document.getElementById("email-body");

const clearBtn = document.getElementById("clear-btn");
const downloadBtn = document.getElementById("download-report-btn");

const resultEmpty = document.getElementById("result-empty");
const resultContent = document.getElementById("result-content");

const verdictRow = document.getElementById("verdict-row");
const verdictValue = document.getElementById("verdict-value");

const riskScoreEl = document.getElementById("risk-score");
const confidenceScoreEl = document.getElementById("confidence-score");

const reasonList = document.getElementById("reason-list");

const urlsDetectedEl = document.getElementById("urls-detected");
const urlsSuspiciousEl = document.getElementById("urls-suspicious");

const keywordList = document.getElementById("keyword-list");

let lastAnalysis = null;


/* =========================================================
   PHISHING KEYWORDS
   ========================================================= */

const phishingKeywords = [

  /* Account verification */
  "verify your account",
  "verify account",
  "account verification required",
  "account verification",
  "confirm your account",
  "confirm account details",
  "confirm your identity",
  "verify your identity",
  "identity verification required",
  "complete verification",
  "complete account verification",
  "account verification pending",
  "verification required",
  "verification is required",
  "verify now",
  "verify immediately",
  "validate your account",
  "validate your identity",
  "authenticate your account",
  "revalidate your account",

  /* Account restriction */
  "account suspended",
  "account will be suspended",
  "account has been suspended",
  "account locked",
  "account will be locked",
  "account has been locked",
  "account blocked",
  "account restricted",
  "account access restricted",
  "account temporarily restricted",
  "account terminated",
  "account will be terminated",
  "account disabled",
  "account will be disabled",
  "account deactivated",
  "account will be deactivated",
  "account closure",
  "account will be closed",
  "your account will be closed",
  "your account will be deleted",
  "access will be revoked",
  "access has been restricted",
  "access has been suspended",

  /* Security alerts */
  "security alert",
  "security warning",
  "security notice",
  "security notification",
  "security verification",
  "security check required",
  "security action required",
  "security issue detected",
  "security problem detected",
  "unusual activity",
  "suspicious activity",
  "suspicious sign in",
  "suspicious login",
  "unusual sign in",
  "unusual login",
  "unrecognized login",
  "unrecognized sign in",
  "unrecognized device",
  "unknown device",
  "unknown login",
  "unauthorized access",
  "unauthorized login",
  "unauthorized activity",
  "unauthorized transaction",
  "suspicious transaction",
  "fraudulent activity detected",
  "potential fraud detected",
  "possible fraud detected",

  /* Login / password */
  "reset your password",
  "password reset required",
  "password expires",
  "password has expired",
  "password will expire",
  "password verification",
  "verify your password",
  "confirm your password",
  "enter your password",
  "provide your password",
  "submit your password",
  "login attempt",
  "failed login attempt",
  "new login detected",
  "new sign in detected",
  "sign in required",
  "login required",
  "confirm login",
  "confirm sign in",
  "secure your account",
  "protect your account",
  "restore account access",
  "recover your account",

  /* Payment / banking */
  "update payment information",
  "update your payment information",
  "verify payment",
  "verify your payment",
  "confirm payment",
  "confirm your payment",
  "payment verification required",
  "payment method expired",
  "payment method has expired",
  "payment failed",
  "payment could not be processed",
  "billing information",
  "billing verification",
  "bank account verification",
  "verify bank account",
  "confirm bank account",
  "verify banking information",
  "confirm banking information",
  "update banking information",
  "update bank details",
  "confirm bank details",
  "bank details required",

  /* Link phishing */
  "click here to verify",
  "click here to confirm",
  "click here to secure",
  "click here to continue",
  "click here to login",
  "click here to sign in",
  "click the link below",
  "click the link",
  "follow the link below",
  "use the link below",
  "verify using the link",
  "complete verification using the link",
  "login using the link",

  /* Consequences */
  "failure to verify",
  "failure to confirm",
  "failure to respond",
  "failure to complete",
  "your access will be restricted",
  "your access will be removed",
  "your account may be locked",
  "your account may be suspended",
  "your account may be disabled",
  "your account may be terminated",
  "service interruption",
  "service will be interrupted",
  "avoid account closure",
  "prevent account suspension",

  /* Time pressure */
  "within 24 hours",
  "within 48 hours",
  "within 12 hours",
  "before midnight",
  "before the deadline",
  "before your account is locked",
  "before your account is suspended"
];


/* =========================================================
   SCAM / FRAUD KEYWORDS
   ========================================================= */

const scamKeywords = [

  "you have won",
  "you are a winner",
  "congratulations you won",
  "claim your prize",
  "claim your reward",
  "claim your winnings",
  "lottery winner",
  "lottery prize",
  "cash prize",
  "grand prize",
  "prize money",
  "winner notification",
  "selected as a winner",
  "selected to receive",
  "exclusive reward",
  "unclaimed prize",

  "guaranteed profit",
  "guaranteed returns",
  "guaranteed income",
  "guaranteed investment",
  "risk free investment",
  "no risk investment",
  "double your money",
  "triple your money",
  "multiply your investment",
  "make money fast",
  "get rich quickly",
  "easy money",
  "passive income opportunity",
  "investment opportunity",
  "exclusive investment opportunity",
  "limited investment opportunity",
  "crypto investment",
  "crypto profits",
  "guaranteed crypto returns",
  "trading opportunity",

  "processing fee",
  "release fee",
  "transfer fee",
  "activation fee",
  "administrative fee",
  "clearance fee",
  "customs fee",
  "pay a fee",
  "send a payment",
  "send money",
  "wire transfer",
  "bank transfer required",
  "payment required before release",
  "fee required to receive",

  "refund available",
  "refund pending",
  "claim your refund",
  "refund is ready",
  "compensation payment",
  "payment recovery",
  "overpayment refund",
  "tax refund",
  "government refund",

  "inheritance",
  "inheritance fund",
  "beneficiary",
  "estate beneficiary",
  "fund transfer",
  "financial assistance",
  "urgent financial help",
  "million dollar inheritance",

  "work from home",
  "earn money from home",
  "earn money online",
  "make money online",
  "easy online income",
  "guaranteed income",
  "no experience required",
  "get paid to",
  "job opportunity",
  "exclusive job offer",

  "donate now",
  "urgent donation",
  "emergency donation",
  "charity donation",
  "help victims",
  "send your donation"
];


/* =========================================================
   SPAM / PROMOTIONAL KEYWORDS
   ========================================================= */

const spamKeywords = [

  "sale",
  "discount",
  "deal",
  "coupon",
  "promotion",
  "promotional",
  "special offer",
  "exclusive offer",
  "limited time offer",
  "free gift",
  "bonus",
  "reward",
  "cashback",
  "newsletter",
  "marketing",
  "advertisement",
  "advertising",
  "unsubscribe",
  "mailing list",
  "buy now",
  "shop now",
  "order now",
  "subscribe now",
  "claim now",
  "join now",
  "get yours",
  "book now",
  "save now",
  "act now",
  "don't miss",
  "hurry",
  "ends soon",
  "offer expires"
];


/* =========================================================
   URGENCY KEYWORDS
   ========================================================= */

const urgencyKeywords = [

  "urgent",
  "urgently",
  "immediately",
  "immediate action",
  "immediate response",
  "act now",
  "action required",
  "action is required",
  "final warning",
  "final notice",
  "last warning",
  "last chance",
  "expires today",
  "expires soon",
  "offer expires",
  "respond immediately",
  "respond now",
  "reply immediately",
  "do not delay",
  "do not ignore",
  "time sensitive",
  "time-sensitive",
  "critical action required",
  "as soon as possible",
  "without delay",
  "right away",
  "today",
  "within 24 hours",
  "within 48 hours",
  "within 12 hours",
  "before it is too late",
  "deadline",
  "immediate attention required"
];


/* =========================================================
   CREDENTIAL / SENSITIVE INFORMATION KEYWORDS
   ========================================================= */

const credentialKeywords = [

  "login credentials",
  "account credentials",
  "user credentials",
  "username and password",
  "username & password",
  "enter your username",
  "enter your password",
  "provide your password",
  "submit your password",
  "confirm your password",
  "current password",
  "account password",
  "login password",

  "security code",
  "verification code",
  "authentication code",
  "authentication token",
  "one time password",
  "one-time password",
  "one time passcode",
  "one-time passcode",
  "otp",
  "mfa code",
  "2fa code",
  "two factor authentication code",
  "six digit code",
  "six-digit code",
  "verification pin",

  "pin",
  "account pin",
  "security pin",

  "credit card number",
  "debit card number",
  "card number",
  "card details",
  "credit card details",
  "debit card details",
  "cvv",
  "cvc",
  "expiration date",
  "expiry date",
  "card verification value",

  "bank account details",
  "bank account number",
  "bank details",
  "banking information",
  "routing number",
  "account number",
  "sort code",
  "ifsc code",

  "social security number",
  "government id",
  "identity document",
  "passport number",
  "driver license",
  "driving licence",
  "date of birth",
  "personal information",
  "personal details"
];


/* =========================================================
   SUSPICIOUS BRAND VARIANTS
   ========================================================= */

const brandVariants = [

  "paypa1",
  "pay-pal",
  "paypal-security",
  "paypal-support",
  "paypal-verification",
  "secure-paypal",

  "micros0ft",
  "micro-soft",
  "microsoft-security",
  "microsoft-support",
  "microsoft-verification",

  "g00gle",
  "google-security",
  "google-support",
  "google-verification",

  "amaz0n",
  "amaz-on",
  "amazon-security",
  "amazon-support",
  "amazon-verification",

  "app1e",
  "apple-security",
  "apple-support",
  "apple-verification",

  "netfl1x",
  "netflix-security",
  "netflix-support",
  "netflix-verification",

  "linkedln",
  "linkedin-security",
  "linkedin-support",

  "faceb00k",
  "facebook-security",
  "facebook-support",
  "instagram-security",
  "instagram-support",

  "bank-security",
  "bank-support",
  "bank-verification",
  "account-security",
  "account-support",
  "security-verification",
  "secure-login",
  "secure-account",
  "security-alert"
];


/* =========================================================
   SUSPICIOUS ACTION PHRASES
   ========================================================= */

const suspiciousActionKeywords = [

  "enter your information",
  "enter your details",
  "provide your information",
  "provide your details",
  "submit your information",
  "confirm your details",
  "confirm personal information",
  "send your information",
  "send your credentials",
  "send your password",
  "send the verification code",
  "send the security code",
  "reply with your",
  "reply with your password",
  "reply with the code",
  "click and verify",
  "click to verify",
  "click to confirm",
  "log in to continue",
  "sign in to continue",
  "verify before continuing",
  "complete the process",
  "complete the security check",
  "complete the verification process"
];


/* =========================================================
   FINANCIAL KEYWORDS
   ========================================================= */

const financialKeywords = [

  "bank account",
  "bank details",
  "banking details",
  "payment details",
  "payment information",
  "card details",
  "card information",
  "credit card",
  "debit card",
  "account number",
  "routing number",
  "wire transfer",
  "bank transfer",
  "payment request",
  "payment confirmation",
  "transaction",
  "transaction detected",
  "transaction failed",
  "transaction declined",
  "unauthorized transaction",
  "refund",
  "invoice",
  "overdue payment",
  "outstanding payment",
  "salary payment",
  "payroll information"
];


/* =========================================================
   SOCIAL ENGINEERING KEYWORDS
   ========================================================= */

const socialEngineeringKeywords = [

  "keep this confidential",
  "do not tell anyone",
  "do not tell your manager",
  "do not discuss this",
  "keep this private",
  "between you and me",
  "urgent favor",
  "quick favor",
  "are you available",
  "need your help",
  "i need your help",
  "send me the code",
  "send me the verification code",
  "send me the gift card",
  "buy gift cards",
  "purchase gift cards",
  "send the gift card code",
  "urgent payment request",
  "wire the money",
  "process this payment"
];


/* =========================================================
   EVENTS
   ========================================================= */

if (form) {
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    runAnalysis();
  });
}

if (clearBtn) {
  clearBtn.addEventListener("click", clearForm);
}

if (downloadBtn) {
  downloadBtn.addEventListener("click", function () {
    if (lastAnalysis) {
      generateReport(lastAnalysis);
    }
  });
}


/* =========================================================
   MOBILE NAVIGATION
   ========================================================= */

function initializeMobileNavigation() {

  const toggleButtons = document.querySelectorAll(
    ".nav-toggle, .menu-toggle, #menu-toggle, #hamburger-btn"
  );

  const navigation =
    document.querySelector(".nav-links") ||
    document.querySelector("#nav-links") ||
    document.querySelector("#mobile-menu");

  if (!navigation || toggleButtons.length === 0) {
    return;
  }

  toggleButtons.forEach(function (button) {

    button.addEventListener("click", function () {

      const isOpen =
        navigation.classList.toggle("active");

      button.classList.toggle("active", isOpen);

      button.setAttribute(
        "aria-expanded",
        String(isOpen)
      );
    });

  });

  navigation.querySelectorAll("a").forEach(function (link) {

    link.addEventListener("click", function () {

      navigation.classList.remove("active");

      toggleButtons.forEach(function (button) {

        button.classList.remove("active");

        button.setAttribute(
          "aria-expanded",
          "false"
        );

      });

    });

  });
}

initializeMobileNavigation();


/* =========================================================
   MAIN ANALYSIS
   ========================================================= */

function runAnalysis() {

  try {

    const sender =
      senderInput
        ? senderInput.value.trim()
        : "";

    const subject =
      subjectInput
        ? subjectInput.value.trim()
        : "";

    const body =
      bodyInput
        ? bodyInput.value.trim()
        : "";

    clearFieldErrors();

    if (sender && !isValidEmail(sender)) {

      setFieldError(
        senderInput,
        "Please enter a valid sender email."
      );

      return;
    }

    if (!body) {

      setFieldError(
        bodyInput,
        "Email body is required."
      );

      return;
    }

    const input = {
      sender,
      subject,
      body
    };

    const result =
      analyzeEmail(input);

    lastAnalysis = {
      input,
      result
    };

    renderResults(result);

  } catch (error) {

    console.error(
      "ClueWell Mail analysis error:",
      error
    );

    alert(
      "An error occurred while analyzing the email. Please check the browser console."
    );
  }
}


/* =========================================================
   EMAIL ANALYZER
   ========================================================= */

function analyzeEmail(input) {

  const sender =
    String(input.sender || "")
      .trim()
      .toLowerCase();

  const subject =
    String(input.subject || "")
      .trim()
      .toLowerCase();

  const body =
    String(input.body || "")
      .trim()
      .toLowerCase();

  const text =
    normalizeText(
      `${subject} ${body}`
    );


  /* ---------------------------------------------------------
     MATCH KEYWORDS
     --------------------------------------------------------- */

  const matchedPhishing =
    findMatches(
      text,
      phishingKeywords
    );

  const matchedSpam =
    findMatches(
      text,
      spamKeywords
    );

  const matchedUrgency =
    findMatches(
      text,
      urgencyKeywords
    );

  const matchedCredentials =
    findMatches(
      text,
      credentialKeywords
    );

  const matchedFinancial =
    findMatches(
      text,
      financialKeywords
    );

  const matchedSocialEngineering =
    findMatches(
      text,
      socialEngineeringKeywords
    );

  const matchedSuspiciousActions =
    findMatches(
      text,
      suspiciousActionKeywords
    );


  /* ---------------------------------------------------------
     URL ANALYSIS
     --------------------------------------------------------- */

  const urlMatches =
    body.match(
      /\bhttps?:\/\/[^\s<>"')]+|\bwww\.[^\s<>"')]+/gi
    ) || [];

  const suspiciousUrls =
    urlMatches.filter(
      isSuspiciousUrl
    );


  /* ---------------------------------------------------------
     SENDER ANALYSIS
     --------------------------------------------------------- */

  const senderDomain =
    getSenderDomain(sender);

  const senderLooksOff =
    isUnusualSender(sender);

  const matchedLookalikeBrands =
    brandVariants.filter(
      function (brand) {

        return sender.includes(
          brand.toLowerCase()
        );

      }
    );


  /* =========================================================
     CONTEXTUAL SIGNALS
     ========================================================= */

  const hasVerification =
    /\b(verify|verification|confirm|authenticate|revalidate)\b/
      .test(text);

  const hasThreat =
    /\b(suspended|blocked|locked|restricted|terminated|closure|disabled|deactivated|revoked)\b/
      .test(text);

  const hasPaymentLanguage =
    /\b(payment|invoice|billing|bank|wire transfer|transaction|refund|financial)\b/
      .test(text);

  const hasPaymentAction =
    /\b(pay|payment|send money|send a payment|wire the money|arrange payment|complete payment|payment must be completed|update payment information)\b/
      .test(text);

  const hasPressure =
    matchedUrgency.length > 0 ||
    /\b(avoid additional charges|avoid charges|avoid penalty|penalty|consequences|final notice)\b/
      .test(text);

  const hasSensitiveRequest =
    matchedCredentials.length > 0 ||
    matchedSocialEngineering.length > 0 ||
    /\b(enter your|provide your|submit your|send your)\b/
      .test(text);


  /* =========================================================
     PHISHING SCORE
     ========================================================= */

  let phishingScore = 0;

  /* Direct phishing language */
  phishingScore += Math.min(
    45,
    matchedPhishing.length * 12
  );

  /* Suspicious URLs */
  phishingScore += Math.min(
    35,
    suspiciousUrls.length * 25
  );

  /* Suspicious sender */
  if (senderLooksOff) {
    phishingScore += 10;
  }

  /* Brand impersonation */
  if (matchedLookalikeBrands.length > 0) {
    phishingScore += 35;
  }

  /* Credential harvesting */
  phishingScore += Math.min(
    30,
    matchedCredentials.length * 10
  );

  /* Financial language */
  phishingScore += Math.min(
    24,
    matchedFinancial.length * 6
  );

  /* Social engineering */
  phishingScore += Math.min(
    24,
    matchedSocialEngineering.length * 12
  );

  /* Suspicious actions */
  phishingScore += Math.min(
    20,
    matchedSuspiciousActions.length * 8
  );

  /* Urgency alone is weak evidence */
  phishingScore += Math.min(
    12,
    matchedUrgency.length * 3
  );


  /* =========================================================
     CONTEXT COMBINATIONS
     ========================================================= */

  /* Verification + urgency */
  if (
    hasVerification &&
    matchedUrgency.length > 0
  ) {
    phishingScore += 18;
  }

  /* Verification + threat */
  if (
    hasVerification &&
    hasThreat
  ) {
    phishingScore += 22;
  }

  /* Financial + pressure */
  if (
    hasPaymentLanguage &&
    hasPressure
  ) {
    phishingScore += 18;
  }

  /* Financial + payment action + pressure */
  if (
    hasPaymentLanguage &&
    hasPaymentAction &&
    hasPressure
  ) {
    phishingScore += 18;
  }

  /* Sensitive information + pressure */
  if (
    hasSensitiveRequest &&
    hasPressure
  ) {
    phishingScore += 18;
  }

  /* Suspicious URL + verification/payment */
  if (
    suspiciousUrls.length > 0 &&
    (
      hasVerification ||
      hasPaymentLanguage
    )
  ) {
    phishingScore += 20;
  }

  /* Brand impersonation + sensitive action */
  if (
    matchedLookalikeBrands.length > 0 &&
    (
      hasVerification ||
      hasSensitiveRequest
    )
  ) {
    phishingScore += 20;
  }

  /* Strong financial scam */
  if (
    hasPaymentLanguage &&
    hasPressure &&
    (
      hasPaymentAction ||
      hasSensitiveRequest ||
      suspiciousUrls.length > 0
    )
  ) {
    phishingScore += 12;
  }

  phishingScore =
    Math.min(
      97,
      Math.round(phishingScore)
    );


  /* =========================================================
     STRONG PHISHING CONTEXT
     ========================================================= */

  const strongPhishingContext =

    suspiciousUrls.length > 0 ||

    matchedLookalikeBrands.length > 0 ||

    (
      hasPaymentLanguage &&
      hasPressure &&
      (
        hasPaymentAction ||
        hasSensitiveRequest
      )
    ) ||

    (
      hasVerification &&
      (
        hasThreat ||
        hasSensitiveRequest
      )
    ) ||

    (
      matchedSocialEngineering.length > 0 &&
      hasPressure
    );
  /* =========================================================
     SPAM SCORE
     ========================================================= */

  let spamScore = 0;


  /* ---------------------------------------------------------
     Helper: check whether any phrase exists
     --------------------------------------------------------- */

  function hasAnySpamPhrase(text, phrases) {
    return phrases.some(function (phrase) {
      return text.includes(phrase);
    });
  }


  /* ---------------------------------------------------------
     1. DIRECT SPAM / PROMOTIONAL KEYWORDS
     --------------------------------------------------------- */

  const spamMatches = spamKeywords.filter(function (keyword) {
    return text.includes(
      normalizeText(keyword)
    );
  });


  spamScore += Math.min(
    50,
    spamMatches.length * 15
  );


  /* ---------------------------------------------------------
     2. PROMOTIONAL LANGUAGE
     --------------------------------------------------------- */

  const promotionalPhrases = [

    "sale",
    "sales",
    "discount",
    "deal",
    "coupon",
    "promotion",
    "promotional",
    "special offer",
    "exclusive offer",
    "limited time",
    "limited time offer",
    "free gift",
    "bonus",
    "reward",
    "cashback",
    "clearance",
    "mega sale",
    "flash sale",
    "festive sale",
    "holiday sale",
    "special deal",
    "best deal",
    "huge discount",
    "big discount",
    "free shipping",
    "save money",
    "save big",
    "great savings",
    "massive savings"
  ];


  const hasPromotionalLanguage =
    hasAnySpamPhrase(
      text,
      promotionalPhrases
    );


  if (hasPromotionalLanguage) {
    spamScore += 20;
  }


  /* ---------------------------------------------------------
     3. MARKETING / NEWSLETTER
     --------------------------------------------------------- */

  const marketingPhrases = [

    "newsletter",
    "marketing",
    "advertisement",
    "advertising",
    "marketing campaign",
    "promotional campaign",
    "promotional email",
    "subscribe",
    "unsubscribe",
    "mailing list",
    "offers",
    "promotions",
    "new products",
    "latest products",
    "featured products",
    "product update",
    "special promotion",
    "customer offer"
  ];


  const hasMarketingLanguage =
    hasAnySpamPhrase(
      text,
      marketingPhrases
    );


  if (hasMarketingLanguage) {
    spamScore += 20;
  }


  /* ---------------------------------------------------------
     4. COMMERCIAL CALL TO ACTION
     --------------------------------------------------------- */

  const commercialPhrases = [

    "buy now",
    "shop now",
    "order now",
    "subscribe now",
    "claim now",
    "click here",
    "join now",
    "get yours",
    "book now",
    "start saving",
    "save now",
    "learn more",
    "get started",
    "purchase now",
    "grab yours",
    "don't miss",
    "do not miss",
    "shop today",
    "buy today",
    "order today",
    "claim your offer",
    "get your offer",
    "redeem now",
    "redeem your offer"
  ];


  const hasCommercialAction =
    hasAnySpamPhrase(
      text,
      commercialPhrases
    );


  if (hasCommercialAction) {
    spamScore += 20;
  }


  /* ---------------------------------------------------------
     5. PROMOTIONAL PRESSURE
     --------------------------------------------------------- */

  const promotionalPressurePhrases = [

    "limited time",
    "act now",
    "don't miss",
    "do not miss",
    "hurry",
    "ends soon",
    "offer expires",
    "expires soon",
    "today only",
    "this weekend only",
    "last chance",
    "final hours",
    "while supplies last",
    "only today",
    "ending soon",
    "don't wait",
    "do not wait"
  ];


  const hasPromotionalPressure =
    hasAnySpamPhrase(
      text,
      promotionalPressurePhrases
    );


  if (hasPromotionalPressure) {
    spamScore += 15;
  }


  /* ---------------------------------------------------------
     6. UNSUBSCRIBE
     --------------------------------------------------------- */

  if (
    text.includes("unsubscribe")
  ) {
    spamScore += 15;
  }


  /* ---------------------------------------------------------
     7. DISCOUNT PERCENTAGE
     --------------------------------------------------------- */

  const hasDiscountPercentage =
    /\b\d{1,3}\s*%\s*(off|discount)\b/i.test(
      text
    );


  if (hasDiscountPercentage) {
    spamScore += 20;
  }


  /* ---------------------------------------------------------
     8. MONEY SAVING LANGUAGE
     --------------------------------------------------------- */

  const moneySavingPhrases = [

    "save $",
    "save ₹",
    "save rs",
    "save up to",
    "save upto",
    "get $",
    "get ₹",
    "only $",
    "only ₹",
    "starting at",
    "special price",
    "lowest price",
    "best price",
    "cheap price",
    "exclusive price"
  ];


  if (
    hasAnySpamPhrase(
      text,
      moneySavingPhrases
    )
  ) {
    spamScore += 15;
  }


  /* ---------------------------------------------------------
     9. PROMOTIONAL SUBJECT
     --------------------------------------------------------- */

  const promotionalSubjectPhrases = [

    "sale",
    "discount",
    "offer",
    "deal",
    "coupon",
    "cashback",
    "reward",
    "promotion",
    "free",
    "bonus",
    "shopping",
    "save",
    "special price",
    "limited time",
    "exclusive"
  ];


  const promotionalSubject =
    hasAnySpamPhrase(
      subject,
      promotionalSubjectPhrases
    );


  if (promotionalSubject) {
    spamScore += 10;
  }


  /* ---------------------------------------------------------
     10. STRONG SPAM COMBINATIONS
     --------------------------------------------------------- */

  /*
     Promotion + commercial action
  */

  if (
    hasPromotionalLanguage &&
    hasCommercialAction
  ) {
    spamScore += 20;
  }


  /*
     Marketing + promotion
  */

  if (
    hasMarketingLanguage &&
    hasPromotionalLanguage
  ) {
    spamScore += 15;
  }


  /*
     Promotion + urgency
  */

  if (
    hasPromotionalLanguage &&
    hasPromotionalPressure
  ) {
    spamScore += 15;
  }


  /*
     Marketing + commercial action
  */

  if (
    hasMarketingLanguage &&
    hasCommercialAction
  ) {
    spamScore += 15;
  }


  /*
     Discount + commercial action
  */

  if (
    hasDiscountPercentage &&
    hasCommercialAction
  ) {
    spamScore += 15;
  }


  /* ---------------------------------------------------------
     FINAL SPAM SCORE
     --------------------------------------------------------- */

  spamScore = Math.min(
    95,
    Math.round(spamScore)
  );
  /* =========================================================
     FINAL CLASSIFICATION
     ========================================================= */

  let verdict = "legitimate";

  let riskScore = 3;

  let confidence = 94;

  /* ---------------------------------------------------------
     PHISHING
     --------------------------------------------------------- */
  /* ---------------------------------------------------------
     PHISHING
     --------------------------------------------------------- */

  if (
    phishingScore >= 50 ||
    strongPhishingContext
  ) {

    verdict = "phishing";

    riskScore = Math.max(
      50,
      phishingScore
    );

    const evidenceCount =
      matchedPhishing.length +
      matchedCredentials.length +
      matchedFinancial.length +
      matchedSocialEngineering.length +
      suspiciousUrls.length +
      matchedLookalikeBrands.length;

    confidence = Math.min(
      99,
      Math.max(
        82,
        82 +
        evidenceCount * 2 +
        (hasPressure ? 3 : 0)
      )
    );
  }


  /* ---------------------------------------------------------
     SPAM
     --------------------------------------------------------- */

  else if (spamScore >= 25) {

    verdict = "spam";

    riskScore = Math.min(
      95,
      Math.max(
        30,
        spamScore
      )
    );

    confidence = Math.min(
      97,
      Math.max(
        78,
        80 +
        spamMatches.length * 3
      )
    );
  }


  /* ---------------------------------------------------------
     LEGITIMATE
     --------------------------------------------------------- */

  else {

    const weakRisk =
      Math.min(
        15,
        matchedPhishing.length * 3
      ) +

      Math.min(
        8,
        matchedUrgency.length * 2
      ) +

      Math.min(
        8,
        matchedFinancial.length * 2
      ) +

      Math.min(
        8,
        matchedCredentials.length * 2
      ) +

      Math.min(
        8,
        suspiciousUrls.length * 3
      ) +

      (senderLooksOff ? 5 : 0);

    riskScore = Math.min(
      49,
      Math.max(
        3,
        Math.round(weakRisk)
      )
    );

    confidence = Math.min(
      97,
      Math.max(
        65,
        96 - Math.round(
          riskScore * 0.5
        )
      )
    );
  }
  /* =========================================================
     DETECTION REASONS
     ========================================================= */

  const reasons = [];

  if (
    matchedPhishing.length > 0
  ) {
    reasons.push(
      `Phishing-related keywords detected: ${matchedPhishing.join(", ")}`
    );
  }

  if (
    matchedSpam.length > 0
  ) {
    reasons.push(
      `Spam-related keywords detected: ${matchedSpam.join(", ")}`
    );
  }

  if (
    matchedUrgency.length > 0
  ) {
    reasons.push(
      `Urgency indicators detected: ${matchedUrgency.join(", ")}`
    );
  }

  if (
    matchedCredentials.length > 0
  ) {
    reasons.push(
      `Credential-related terms detected: ${matchedCredentials.join(", ")}`
    );
  }

  if (
    matchedFinancial.length > 0
  ) {
    reasons.push(
      `Financial/payment language detected: ${matchedFinancial.join(", ")}`
    );
  }

  if (
    matchedSocialEngineering.length > 0
  ) {
    reasons.push(
      `Social-engineering language detected: ${matchedSocialEngineering.join(", ")}`
    );
  }

  if (
    matchedSuspiciousActions.length > 0
  ) {
    reasons.push(
      `Suspicious action phrases detected: ${matchedSuspiciousActions.join(", ")}`
    );
  }

  if (
    hasPaymentLanguage &&
    hasPressure
  ) {
    reasons.push(
      "Financial language is combined with urgency or pressure."
    );
  }

  if (
    hasVerification &&
    hasThreat
  ) {
    reasons.push(
      "Verification language is combined with an account-access consequence."
    );
  }

  if (
    hasSensitiveRequest &&
    hasPressure
  ) {
    reasons.push(
      "A request for sensitive information is combined with pressure to act."
    );
  }

  if (
    suspiciousUrls.length > 0
  ) {
    reasons.push(
      `${suspiciousUrls.length} suspicious URL(s) detected`
    );
  }

  if (
    senderLooksOff
  ) {
    reasons.push(
      "Sender format or domain pattern appears unusual"
    );
  }

  if (
    matchedLookalikeBrands.length > 0
  ) {
    reasons.push(
      `Possible brand impersonation detected: ${matchedLookalikeBrands.join(", ")}`
    );
  }

  if (
    urlMatches.length === 0
  ) {
    reasons.push(
      "No URLs detected in the email body"
    );
  }

  if (
    verdict === "legitimate"
  ) {

    if (
      reasons.length === 0 ||
      (
        matchedFinancial.length === 0 &&
        matchedPhishing.length === 0 &&
        matchedUrgency.length === 0 &&
        matchedCredentials.length === 0 &&
        suspiciousUrls.length === 0 &&
        !senderLooksOff
      )
    ) {

      reasons.push(
        "No strong phishing or spam indicators detected"
      );

    } else {

      reasons.push(
        "Some weak indicators were detected, but the phishing/spam thresholds were not reached."
      );
    }
  }

  if (
    verdict === "spam"
  ) {
    reasons.push(
      "Promotional/spam indicators are present without enough evidence of credential theft or deceptive account/payment action."
    );
  }

  if (
    reasons.length === 0
  ) {
    reasons.push(
      "No significant indicators detected"
    );
  }


  /* =========================================================
     RETURN RESULT
     ========================================================= */

  return {

    verdict,

    riskScore,

    confidence,

    reasons,

    matchedPhishing,

    matchedSpam,

    matchedUrgency,

    matchedCredentials,

    matchedFinancial,

    matchedSocialEngineering,

    matchedSuspiciousActions,

    matchedLookalikeBrands,

    urlMatches,

    suspiciousUrls,

    senderDomain,

    phishingScore,

    spamScore
  };
}


/* =========================================================
   TEXT HELPERS
   ========================================================= */

function normalizeText(value) {

  return String(value || "")
    .toLowerCase()
    .replace(/[“”‘’]/g, "'")
    .replace(/[^a-z0-9@._:/-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function containsPhrase(text, phrase) {

  const normalizedText =
    normalizeText(text);

  const normalizedPhrase =
    normalizeText(phrase);

  if (!normalizedPhrase) {
    return false;
  }

  const escaped =
    normalizedPhrase.replace(
      /[.*+?^${}()|[\]\\]/g,
      "\\$&"
    );

  const pattern =
    new RegExp(
      `(?:^|\\s)${escaped}(?=\\s|[.,!?;:()"'/%]|$)`,
      "i"
    );

  return pattern.test(
    normalizedText
  );
}

function findMatches(
  text,
  keywords
) {

  return keywords.filter(
    function (keyword) {

      return containsPhrase(
        text,
        keyword
      );

    }
  );
}


/* =========================================================
   URL ANALYSIS
   ========================================================= */

function isSuspiciousUrl(url) {

  try {

    const cleanUrl =
      String(url).replace(
        /[.,!?;:]+$/g,
        ""
      );

    const parsedUrl =
      new URL(
        cleanUrl.startsWith("www.")
          ? `https://${cleanUrl}`
          : cleanUrl
      );

    const hostname =
      parsedUrl.hostname.toLowerCase();


    /* IP address URL */

    const hasIpAddress =
      /^(?:\d{1,3}\.){3}\d{1,3}$/
        .test(hostname);


    /* Punycode */

    const hasPunycode =
      hostname.includes("xn--");


    /* Suspicious domain terms */

    const suspiciousTerms = [

      "verify-",
      "-verify",

      "secure-",
      "-secure",

      "account-",
      "-account",

      "login-",
      "-login",

      "update-",
      "-update",

      "support-",
      "-support",

      "billing-",
      "-billing",

      "payment-",
      "-payment"
    ];

    const hasSuspiciousTerm =
      suspiciousTerms.some(
        function (term) {

          return hostname.includes(
            term
          );

        }
      );


    /* Deep subdomain */

    const hostnameParts =
      hostname.split(".");

    const hasVeryLongSubdomain =
      hostnameParts.length >= 5;


    /* @ inside URL */

    const hasAtSymbol =
      cleanUrl.includes("@");


    return (

      hasIpAddress ||

      hasPunycode ||

      hasSuspiciousTerm ||

      hasVeryLongSubdomain ||

      hasAtSymbol

    );

  } catch (error) {

    return true;
  }
}


/* =========================================================
   SENDER HELPERS
   ========================================================= */

function getSenderDomain(sender) {

  if (!sender.includes("@")) {
    return "Unknown";
  }

  return sender
    .split("@")
    .slice(1)
    .join("@");
}


function isUnusualSender(sender) {

  if (!sender) {
    return false;
  }

  const localPart =
    sender.split("@")[0] || "";

  const domain =
    getSenderDomain(sender);


  /* Too many numbers */

  const hasManyNumbers =
    (localPart.match(/\d/g) || [])
      .length >= 4;


  /* Repeated hyphens */

  const hasRepeatedHyphens =
    domain.includes("--");


  /* Suspicious domain structures */

  const hasSuspiciousDomainPattern =

    domain.startsWith("-") ||

    domain.endsWith("-") ||

    domain.includes("secure-login") ||

    domain.includes("account-verify");


  return (

    hasManyNumbers ||

    hasRepeatedHyphens ||

    hasSuspiciousDomainPattern

  );
}


function isValidEmail(email) {

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    .test(email);
}


/* =========================================================
   RENDER RESULTS
   ========================================================= */

function renderResults(result) {

  if (resultEmpty) {

    resultEmpty.style.display =
      "none";
  }

  if (resultContent) {

    resultContent.style.display =
      "block";
  }


  /* Verdict */

  if (verdictRow) {

    verdictRow.className =
      `verdict-row ${result.verdict}`;
  }

  if (verdictValue) {

    verdictValue.textContent =
      result.verdict.toUpperCase();
  }


  /* Scores */

  if (riskScoreEl) {

    riskScoreEl.textContent =
      `${result.riskScore}%`;
  }

  if (confidenceScoreEl) {

    confidenceScoreEl.textContent =
      `${result.confidence}%`;
  }


  /* URLs */

  if (urlsDetectedEl) {

    urlsDetectedEl.textContent =
      result.urlMatches.length;
  }

  if (urlsSuspiciousEl) {

    urlsSuspiciousEl.textContent =
      result.suspiciousUrls.length;
  }


  /* Detection reasons */

  if (reasonList) {

    reasonList.innerHTML = "";

    result.reasons.forEach(
      function (reason) {

        const item =
          document.createElement("li");

        item.textContent =
          reason;

        reasonList.appendChild(
          item
        );
      }
    );
  }


  /* =======================================================
     KEYWORD ANALYSIS
     ======================================================= */

  if (keywordList) {

    keywordList.innerHTML = "";

    const groups = [

      {
        title: "Phishing Keywords",
        values: result.matchedPhishing,
        className: "phishing"
      },

      {
        title: "Spam Keywords",
        values: result.matchedSpam,
        className: "spam"
      },

      {
        title: "Urgency Keywords",
        values: result.matchedUrgency,
        className: "urgency"
      },

      {
        title: "Credential Keywords",
        values: result.matchedCredentials,
        className: "credentials"
      },

      {
        title: "Financial Keywords",
        values: result.matchedFinancial,
        className: "financial"
      },

      {
        title: "Social Engineering Keywords",
        values: result.matchedSocialEngineering,
        className: "social"
      },

      {
        title: "Suspicious Action Keywords",
        values: result.matchedSuspiciousActions,
        className: "suspicious-action"
      },

      {
        title: "Brand Indicators",
        values: result.matchedLookalikeBrands,
        className: "brand"
      }
    ];


    let hasKeywords = false;

    groups.forEach(
      function (group) {

        const uniqueValues =
          [
            ...new Set(
              group.values || []
            )
          ];

        if (
          uniqueValues.length === 0
        ) {
          return;
        }

        hasKeywords = true;

        const groupContainer =
          document.createElement("div");

        groupContainer.className =
          "keyword-group";


        const heading =
          document.createElement("div");

        heading.textContent =
          group.title;

        heading.className =
          "keyword-group-heading";

        groupContainer.appendChild(
          heading
        );


        const chipsContainer =
          document.createElement("div");

        chipsContainer.className =
          "keyword-chips";


        uniqueValues.forEach(
          function (keyword) {

            const item =
              document.createElement("span");

            item.textContent =
              keyword;

            item.className =
              `keyword-chip flagged ${group.className}`;

            chipsContainer.appendChild(
              item
            );
          }
        );


        groupContainer.appendChild(
          chipsContainer
        );

        keywordList.appendChild(
          groupContainer
        );
      }
    );


    if (!hasKeywords) {

      const item =
        document.createElement("div");

      item.textContent =
        "No matching keywords detected";

      item.className =
        "keyword-empty";

      keywordList.appendChild(
        item
      );
    }
  }
}


/* =========================================================
   FORM ERRORS
   ========================================================= */

function setFieldError(
  inputElement,
  message
) {

  if (!inputElement) {
    return;
  }

  inputElement.classList.add(
    "input-error"
  );

  inputElement.setAttribute(
    "aria-invalid",
    "true"
  );


  let errorElement =

    inputElement.parentElement
      ? inputElement.parentElement
        .querySelector(
          ".field-error"
        )
      : null;


  if (!errorElement) {

    errorElement =
      document.createElement(
        "small"
      );

    errorElement.className =
      "field-error";

    if (
      inputElement.parentElement
    ) {

      inputElement.parentElement.appendChild(
        errorElement
      );
    }
  }

  errorElement.textContent =
    message;
}


function clearFieldErrors() {

  document
    .querySelectorAll(
      ".input-error"
    )
    .forEach(
      function (element) {

        element.classList.remove(
          "input-error"
        );

        element.removeAttribute(
          "aria-invalid"
        );
      }
    );


  document
    .querySelectorAll(
      ".field-error"
    )
    .forEach(
      function (element) {

        element.remove();
      }
    );
}


/* =========================================================
   CLEAR FORM
   ========================================================= */

function clearForm() {

  if (form) {
    form.reset();
  }

  clearFieldErrors();

  if (resultEmpty) {

    resultEmpty.style.display =
      "block";
  }

  if (resultContent) {

    resultContent.style.display =
      "none";
  }

  lastAnalysis = null;
}


/* =========================================================
   PDF REPORT
   ========================================================= */

function loadImage(src) {

  return new Promise(
    function (resolve) {

      const image =
        new Image();

      image.onload =
        function () {
          resolve(image);
        };

      image.onerror =
        function () {
          resolve(null);
        };

      image.src = src;
    }
  );
}


async function generateReport(
  analysis
) {

  if (
    !analysis ||
    !window.jspdf ||
    !window.jspdf.jsPDF
  ) {

    alert(
      "PDF library is not loaded."
    );

    return;
  }


  const doc =
    new window.jspdf.jsPDF({
      unit: "pt",
      format: "a4"
    });


  const margin = 48;

  const pageWidth =
    doc.internal.pageSize.getWidth();

  const pageHeight =
    doc.internal.pageSize.getHeight();

  const contentWidth =
    pageWidth - margin * 2;

  let y = 105;

  const input =
    analysis.input;

  const result =
    analysis.result;


  /* =======================================================
     TEXT HELPER
     ======================================================= */

  function addText(
    text,
    size = 10,
    style = "normal",
    gapAfter = 6
  ) {

    doc.setFont(
      "helvetica",
      style
    );

    doc.setFontSize(
      size
    );

    const lines =
      doc.splitTextToSize(
        String(
          text || "Not provided"
        ),
        contentWidth
      );

    lines.forEach(
      function (line) {

        if (
          y + size + 8 >
          pageHeight - margin
        ) {

          doc.addPage();

          y = margin;
        }

        doc.text(
          line,
          margin,
          y
        );

        y += size + 5;
      }
    );

    y += gapAfter;
  }


  function addSectionHeading(
    text
  ) {

    addText(
      text,
      12,
      "bold",
      8
    );
  }


  /* =======================================================
     LOGO
     ======================================================= */

  const logo =
    await loadImage(
      "assests/cluewell-mail.png"
    );

  if (logo) {

    doc.addImage(
      logo,
      "PNG",
      margin,
      30,
      75,
      60
    );
  }


  /* =======================================================
     TITLE
     ======================================================= */

  doc.setFont(
    "helvetica",
    "bold"
  );

  doc.setFontSize(
    20
  );

  doc.text(
    "ClueWell-Mail",
    margin + 90,
    65
  );


  doc.setFont(
    "helvetica",
    "normal"
  );

  doc.setFontSize(
    13
  );

  doc.text(
    "Email Threat Analysis Report",
    margin + 72,
    85
  );

  y = 125;


  /* =======================================================
     EMAIL DETAILS
     ======================================================= */

  addSectionHeading(
    "Email Details"
  );

  addText(
    `Sender: ${input.sender || "Not provided"}`
  );

  addText(
    `Subject: ${input.subject || "Not provided"}`
  );

  addText(
    `Body: ${input.body || "Not provided"}`,
    10,
    "normal",
    12
  );


  /* =======================================================
     VERDICT
     ======================================================= */

  addSectionHeading(
    "Verdict and Scoring"
  );

  addText(
    `Verdict: ${result.verdict.toUpperCase()}`,
    11,
    "bold"
  );

  addText(
    `Risk Score: ${result.riskScore}%`
  );

  addText(
    `Rule-Based Confidence: ${result.confidence}%`
  );

  addText(
    `Phishing Score: ${result.phishingScore}`
  );

  addText(
    `Spam Score: ${result.spamScore}`,
    10,
    "normal",
    12
  );


  /* =======================================================
     DETECTION REASONS
     ======================================================= */

  addSectionHeading(
    "Detection Reasons"
  );

  result.reasons.forEach(
    function (reason) {

      addText(
        `• ${reason}`,
        10,
        "normal",
        2
      );
    }
  );

  y += 8;


  /* =======================================================
     URL ANALYSIS
     ======================================================= */

  addSectionHeading(
    "URL Analysis"
  );

  addText(
    `URLs Detected: ${result.urlMatches.length}`
  );

  addText(
    `Suspicious URLs: ${result.suspiciousUrls.length}`
  );


  if (
    result.urlMatches.length > 0
  ) {

    result.urlMatches.forEach(
      function (url) {

        const status =
          result.suspiciousUrls.includes(
            url
          )
            ? "Suspicious"
            : "Not flagged";

        addText(
          `${url} — ${status}`,
          9,
          "normal",
          2
        );
      }
    );

  } else {

    addText(
      "No URLs detected."
    );
  }

  y += 8;


  /* =======================================================
     KEYWORD ANALYSIS
     ======================================================= */

  addSectionHeading(
    "Keyword Analysis"
  );

  addText(
    `Phishing Keywords: ${result.matchedPhishing.join(", ") ||
    "None"
    }`
  );

  addText(
    `Spam Keywords: ${result.matchedSpam.join(", ") ||
    "None"
    }`
  );

  addText(
    `Urgency Keywords: ${result.matchedUrgency.join(", ") ||
    "None"
    }`
  );

  addText(
    `Credential Keywords: ${result.matchedCredentials.join(", ") ||
    "None"
    }`
  );

  addText(
    `Financial Keywords: ${(result.matchedFinancial || []).join(", ") ||
    "None"
    }`
  );

  addText(
    `Social Engineering Keywords: ${(result.matchedSocialEngineering || []).join(", ") ||
    "None"
    }`
  );

  addText(
    `Suspicious Action Keywords: ${(result.matchedSuspiciousActions || []).join(", ") ||
    "None"
    }`
  );

  addText(
    `Possible Brand Indicators: ${result.matchedLookalikeBrands.join(", ") ||
    "None"
    }`,
    10,
    "normal",
    12
  );


  /* =======================================================
     DISCLAIMER
     ======================================================= */

  addSectionHeading(
    "Disclaimer"
  );

  addText(
    "ClueWell Mail uses client-side keyword and rule-based analysis. The result is an indication only and should not be treated as a guaranteed security decision.",
    9,
    "normal",
    5
  );


  /* =======================================================
     FOOTER
     ======================================================= */

  doc.setFont(
    "helvetica",
    "normal"
  );

  doc.setFontSize(
    8
  );

  const generatedText =
    `Generated: ${new Date().toLocaleString()}`;

  doc.text(
    generatedText,
    pageWidth - margin,
    pageHeight - 25,
    {
      align: "right"
    }
  );


  /* =======================================================
     SAVE PDF
     ======================================================= */

  doc.save(
    "ClueWell-Mail-report.pdf"
  );
}