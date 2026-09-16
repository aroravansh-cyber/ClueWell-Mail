/* =========================================================
   ClueWell Mail
   Rule-Based Email Phishing, Spam & Legitimate Analyzer
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
   KEYWORDS
   ========================================================= */
// ============================================================
// PHISHING DETECTION KEYWORDS
// ============================================================

const phishingKeywords = [

  // Account verification
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

  // Account restriction / suspension
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

  // Security alerts
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

  // Login / password
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

  // Payment / banking
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

  // Link-based phishing
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

  // Consequences
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

  // Time pressure
  "within 24 hours",
  "within 48 hours",
  "within 12 hours",
  "before midnight",
  "before the deadline",
  "before your account is locked",
  "before your account is suspended"
];


// ============================================================
// SCAM / FRAUD KEYWORDS
// ============================================================

const scamKeywords = [

  // Prize / lottery
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

  // Investment scams
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

  // Advance-fee scams
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

  // Fake refund / compensation
  "refund available",
  "refund pending",
  "claim your refund",
  "refund is ready",
  "compensation payment",
  "payment recovery",
  "overpayment refund",
  "tax refund",
  "government refund",

  // Romance / inheritance / unexpected money
  "inheritance",
  "inheritance fund",
  "beneficiary",
  "estate beneficiary",
  "fund transfer",
  "financial assistance",
  "urgent financial help",
  "million dollar inheritance",

  // Job / income scams
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

  // Fake charity / donations
  "donate now",
  "urgent donation",
  "emergency donation",
  "charity donation",
  "help victims",
  "send your donation"
];


// ============================================================
// SPAM / PROMOTIONAL KEYWORDS
// ============================================================

const spamKeywords = [

  "exclusive offer",
  "special offer",
  "limited offer",
  "amazing offer",
  "discount",
  "big discount",
  "free gift",
  "free bonus",
  "buy now",
  "shop now",
  "limited time",
  "last chance",
  "huge savings",
  "best deal",
  "deal of the day",
  "promo code",
  "coupon code",
  "cashback",
  "special promotion",
  "seasonal sale",
  "flash sale",
  "mega sale",
  "clearance sale",
  "save up to",
  "lowest price",
  "exclusive discount",
  "free trial",
  "subscribe now",
  "unsubscribe",
  "special price",
  "today only"
];


// ============================================================
// URGENCY KEYWORDS
// ============================================================

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


// ============================================================
// CREDENTIAL / SENSITIVE INFORMATION KEYWORDS
// ============================================================

const credentialKeywords = [

  // Login credentials
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

  // OTP / MFA
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

  // PIN
  "pin",
  "account pin",
  "security pin",
  "verification pin",

  // Card information
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

  // Banking
  "bank account details",
  "bank account number",
  "bank details",
  "banking information",
  "routing number",
  "account number",
  "sort code",
  "ifsc code",

  // Personal information
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


// ============================================================
// SUSPICIOUS SENDER / DOMAIN PATTERNS
// ============================================================

const brandVariants = [

  // PayPal
  "paypa1",
  "pay-pal",
  "paypal-security",
  "paypal-support",
  "paypal-verification",
  "secure-paypal",

  // Microsoft
  "micros0ft",
  "micro-soft",
  "microsoft-security",
  "microsoft-support",
  "microsoft-verification",

  // Google
  "g00gle",
  "google-security",
  "google-support",
  "google-verification",

  // Amazon
  "amaz0n",
  "amaz-on",
  "amazon-security",
  "amazon-support",
  "amazon-verification",

  // Apple
  "app1e",
  "apple-security",
  "apple-support",
  "apple-verification",

  // Netflix
  "netfl1x",
  "netflix-security",
  "netflix-support",
  "netflix-verification",

  // LinkedIn
  "linkedln",
  "linkedin-security",
  "linkedin-support",

  // Social media
  "faceb00k",
  "facebook-security",
  "facebook-support",
  "instagram-security",
  "instagram-support",

  // Generic impersonation
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


// ============================================================
// SUSPICIOUS ACTION PHRASES
// ============================================================

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


// ============================================================
// SUSPICIOUS FINANCIAL LANGUAGE
// ============================================================

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


// ============================================================
// SOCIAL ENGINEERING KEYWORDS
// ============================================================

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
      const isOpen = navigation.classList.toggle("active");

      button.classList.toggle("active", isOpen);
      button.setAttribute("aria-expanded", String(isOpen));
    });
  });

  navigation.querySelectorAll("a").forEach(function (link) {
    link.addEventListener("click", function () {
      navigation.classList.remove("active");

      toggleButtons.forEach(function (button) {
        button.classList.remove("active");
        button.setAttribute("aria-expanded", "false");
      });
    });
  });
}

initializeMobileNavigation();


/* =========================================================
   ANALYSIS
   ========================================================= */

function runAnalysis() {
  const sender = senderInput ? senderInput.value.trim() : "";
  const subject = subjectInput ? subjectInput.value.trim() : "";
  const body = bodyInput ? bodyInput.value.trim() : "";

  clearFieldErrors();

  if (sender && !isValidEmail(sender)) {
    setFieldError(senderInput, "Please enter a valid sender email.");
    return;
  }

  if (!body) {
    setFieldError(bodyInput, "Email body is required.");
    return;
  }

  const input = {
    sender,
    subject,
    body
  };

  const result = analyzeEmail(input);

  lastAnalysis = {
    input,
    result
  };

  renderResults(result);
}

function analyzeEmail(input) {
  const sender = input.sender.toLowerCase();
  const subject = input.subject.toLowerCase();
  const body = input.body.toLowerCase();

  const text = `${subject} ${body}`
    .replace(/\s+/g, " ")
    .trim();

  const matchedPhishing = findMatches(text, phishingKeywords);
  const matchedSpam = findMatches(text, spamKeywords);
  const matchedUrgency = findMatches(text, urgencyKeywords);
  const matchedCredentials = findMatches(text, credentialKeywords);

  const urlMatches =
    input.body.match(/https?:\/\/[^\s<>"')]+/gi) || [];

  const suspiciousUrls = urlMatches.filter(isSuspiciousUrl);

  const senderDomain = getSenderDomain(sender);
  const senderLooksOff = isUnusualSender(sender);

  const matchedLookalikeBrands = brandVariants.filter(function (brand) {
    return sender.includes(brand);
  });

  let phishingScore = 0;

  phishingScore += matchedPhishing.length * 15;
  phishingScore += suspiciousUrls.length * 20;

  if (senderLooksOff) {
    phishingScore += 15;
  }

  if (matchedLookalikeBrands.length > 0) {
    phishingScore += 30;
  }

  phishingScore += matchedUrgency.length * 4;
  phishingScore += matchedCredentials.length * 5;

  const hasVerification =
    text.includes("verify") ||
    text.includes("verification") ||
    text.includes("confirm your account") ||
    text.includes("confirm your identity");

  const hasThreat =
    text.includes("suspended") ||
    text.includes("blocked") ||
    text.includes("locked") ||
    text.includes("restricted") ||
    text.includes("terminated") ||
    text.includes("closure");

  if (hasVerification && matchedUrgency.length > 0) {
    phishingScore += 20;
  }

  if (hasVerification && hasThreat) {
    phishingScore += 20;
  }

  let spamScore = 0;

  spamScore += matchedSpam.length * 7;

  if (matchedSpam.length >= 2) {
    spamScore += 10;
  }

  if (
    text.includes("offer") &&
    (
      text.includes("sale") ||
      text.includes("discount") ||
      text.includes("deal") ||
      text.includes("shop")
    )
  ) {
    spamScore += 15;
  }

  if (
    text.includes("buy now") ||
    text.includes("shop now") ||
    text.includes("subscribe now") ||
    text.includes("coupon code") ||
    text.includes("promo code")
  ) {
    spamScore += 10;
  }

  phishingScore = Math.min(phishingScore, 97);
  spamScore = Math.min(spamScore, 95);

  const indicatorCount =
    matchedPhishing.length +
    matchedSpam.length +
    matchedUrgency.length +
    matchedCredentials.length +
    suspiciousUrls.length +
    (senderLooksOff ? 1 : 0) +
    (matchedLookalikeBrands.length > 0 ? 1 : 0);

  let verdict = "legitimate";
  let riskScore = 3;
  let confidence = 95;

  if (phishingScore >= 50) {
    verdict = "phishing";
    riskScore = phishingScore;

    confidence = Math.min(
      99,
      85 +
      matchedPhishing.length * 2 +
      matchedLookalikeBrands.length * 2 +
      suspiciousUrls.length * 2
    );
  } else if (spamScore >= 30) {
    verdict = "spam";
    riskScore = Math.min(95, 20 + spamScore);

    confidence = Math.min(
      97,
      82 + matchedSpam.length * 2
    );
  } else {
    const keywordRisk =
      matchedPhishing.length * 5 +
      matchedSpam.length * 3 +
      matchedUrgency.length * 4 +
      matchedCredentials.length * 5;

    const urlRisk = suspiciousUrls.length * 12;
    const senderRisk = senderLooksOff ? 8 : 0;
    const brandRisk = matchedLookalikeBrands.length > 0 ? 12 : 0;

    const combinedRisk =
      keywordRisk +
      urlRisk +
      senderRisk +
      brandRisk +
      Math.round(phishingScore * 0.2) +
      Math.round(spamScore * 0.15);

    riskScore = Math.min(
      49,
      Math.max(3, Math.round(combinedRisk))
    );

    confidence = Math.min(
      97,
      Math.max(65, 96 - Math.round(riskScore * 0.6))
    );
  }

  const reasons = [];

  if (matchedPhishing.length > 0) {
    reasons.push(
      `Phishing-related keywords detected: ${matchedPhishing.join(", ")}`
    );
  }

  if (matchedSpam.length > 0) {
    reasons.push(
      `Spam-related keywords detected: ${matchedSpam.join(", ")}`
    );
  }

  if (matchedUrgency.length > 0) {
    reasons.push(
      `Urgency indicators detected: ${matchedUrgency.join(", ")}`
    );
  }

  if (matchedCredentials.length > 0) {
    reasons.push(
      `Credential-related terms detected: ${matchedCredentials.join(", ")}`
    );
  }

  if (suspiciousUrls.length > 0) {
    reasons.push(
      `${suspiciousUrls.length} suspicious URL(s) detected`
    );
  }

  if (senderLooksOff) {
    reasons.push("Sender format appears unusual");
  }

  if (matchedLookalikeBrands.length > 0) {
    reasons.push(
      `Possible brand impersonation detected: ${matchedLookalikeBrands.join(", ")}`
    );
  }

  if (urlMatches.length === 0) {
    reasons.push("No URLs detected in the email body");
  }

  if (verdict === "legitimate") {
    if (indicatorCount === 0) {
      reasons.push(
        "No suspicious phishing, spam, sender, or URL indicators detected"
      );
    } else {
      reasons.push(
        "Weak indicators were detected, but phishing and spam thresholds were not reached"
      );
    }
  }

  if (reasons.length === 0) {
    reasons.push("No significant indicators detected");
  }

  return {
    verdict,
    riskScore,
    confidence,
    reasons,
    matchedPhishing,
    matchedSpam,
    matchedUrgency,
    matchedCredentials,
    matchedLookalikeBrands,
    urlMatches,
    suspiciousUrls,
    senderDomain,
    phishingScore,
    spamScore
  };
}


/* =========================================================
   HELPERS
   ========================================================= */

function findMatches(text, keywords) {
  return keywords.filter(function (keyword) {
    return text.includes(keyword.toLowerCase());
  });
}

function isSuspiciousUrl(url) {
  try {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname.toLowerCase();

    const hasIpAddress =
      /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);

    const hasPunycode = hostname.includes("xn--");

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
      "-update"
    ];

    const hasSuspiciousTerm = suspiciousTerms.some(function (term) {
      return hostname.includes(term);
    });

    return (
      hasIpAddress ||
      hasPunycode ||
      hasSuspiciousTerm
    );
  } catch (error) {
    return true;
  }
}

function getSenderDomain(sender) {
  if (!sender.includes("@")) {
    return "Unknown";
  }

  return sender.split("@")[1];
}

function isUnusualSender(sender) {
  if (!sender) {
    return false;
  }

  const localPart = sender.split("@")[0] || "";
  const domain = getSenderDomain(sender);

  const hasManyNumbers =
    (localPart.match(/\d/g) || []).length >= 4;

  const hasRepeatedHyphens = domain.includes("--");

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
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}


/* =========================================================
   RESULTS
   ========================================================= */


function renderResults(result) {
  if (resultEmpty) {
    resultEmpty.style.display = "none";
  }

  if (resultContent) {
    resultContent.style.display = "block";
  }

  if (verdictRow) {
    verdictRow.className = `verdict-row ${result.verdict}`;
  }

  if (verdictValue) {
    verdictValue.textContent = result.verdict.toUpperCase();
  }

  if (riskScoreEl) {
    riskScoreEl.textContent = `${result.riskScore}%`;
  }

  if (confidenceScoreEl) {
    confidenceScoreEl.textContent = `${result.confidence}%`;
  }

  if (urlsDetectedEl) {
    urlsDetectedEl.textContent = result.urlMatches.length;
  }

  if (urlsSuspiciousEl) {
    urlsSuspiciousEl.textContent = result.suspiciousUrls.length;
  }

  // Detection Reasons
  if (reasonList) {
    reasonList.innerHTML = "";

    result.reasons.forEach(function (reason) {
      const item = document.createElement("li");
      item.textContent = reason;
      reasonList.appendChild(item);
    });
  }

  // Keyword Analysis
  
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
        title: "Brand Indicators",
        values: result.matchedLookalikeBrands,
        className: "brand"
      }
    ];

    let hasKeywords = false;

    groups.forEach(function (group) {
      const uniqueValues = [...new Set(group.values || [])];

      if (uniqueValues.length === 0) {
        return;
      }

      hasKeywords = true;

      // Create separate group container
      const groupContainer = document.createElement("div");
      groupContainer.className = "keyword-group";

      // Create group heading
      const heading = document.createElement("div");
      heading.textContent = group.title;
      heading.className = "keyword-group-heading";

      groupContainer.appendChild(heading);

      // Create chips container
      const chipsContainer = document.createElement("div");
      chipsContainer.className = "keyword-chips";

      uniqueValues.forEach(function (keyword) {
        const item = document.createElement("span");

        item.textContent = keyword;
        item.className = `keyword-chip flagged ${group.className}`;

        chipsContainer.appendChild(item);
      });

      groupContainer.appendChild(chipsContainer);
      keywordList.appendChild(groupContainer);
    });

    if (!hasKeywords) {
      const item = document.createElement("div");
      item.textContent = "No matching keywords detected";
      item.className = "keyword-empty";
      keywordList.appendChild(item);
    }
  }
}


/* =========================================================
   FORM ERRORS
   ========================================================= */

function setFieldError(inputElement, message) {
  if (!inputElement) {
    return;
  }

  inputElement.classList.add("input-error");
  inputElement.setAttribute("aria-invalid", "true");

  let errorElement =
    inputElement.parentElement.querySelector(".field-error");

  if (!errorElement) {
    errorElement = document.createElement("small");
    errorElement.className = "field-error";
    inputElement.parentElement.appendChild(errorElement);
  }

  errorElement.textContent = message;
}

function clearFieldErrors() {
  document.querySelectorAll(".input-error").forEach(function (element) {
    element.classList.remove("input-error");
    element.removeAttribute("aria-invalid");
  });

  document.querySelectorAll(".field-error").forEach(function (element) {
    element.remove();
  });
}

function clearForm() {
  if (form) {
    form.reset();
  }

  clearFieldErrors();

  if (resultEmpty) {
    resultEmpty.style.display = "block";
  }

  if (resultContent) {
    resultContent.style.display = "none";
  }

  lastAnalysis = null;
}


/* =========================================================
   PDF REPORT
   ========================================================= */

function loadImage(src) {
  return new Promise(function (resolve) {
    const image = new Image();

    image.onload = function () {
      resolve(image);
    };

    image.onerror = function () {
      resolve(null);
    };

    image.src = src;
  });
}

async function generateReport(analysis) {
  if (!analysis || !window.jspdf || !window.jspdf.jsPDF) {
    alert("PDF library is not loaded.");
    return;
  }

  const doc = new window.jspdf.jsPDF({
    unit: "pt",
    format: "a4"
  });

  const margin = 48;
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const contentWidth = pageWidth - margin * 2;

  let y = 105;

  const input = analysis.input;
  const result = analysis.result;

  function addText(
    text,
    size = 10,
    style = "normal",
    gapAfter = 6
  ) {
    doc.setFont("helvetica", style);
    doc.setFontSize(size);

    const lines = doc.splitTextToSize(
      String(text || "Not provided"),
      contentWidth
    );

    lines.forEach(function (line) {
      if (y + size + 8 > pageHeight - margin) {
        doc.addPage();
        y = margin;
      }

      doc.text(line, margin, y);
      y += size + 5;
    });

    y += gapAfter;
  }

  function addSectionHeading(text) {
    addText(text, 12, "bold", 8);
  }

  // Load logo
  const logo = await loadImage("assests/cluewell-mail.png");

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

  // Title
  doc.setFont("helvetica", "bold");
  doc.setFontSize(20);

  doc.text(
    "ClueWell-Mail",
    margin + 90,
    65
  );

  // Subtitle
  doc.setFont("helvetica", "normal");
  doc.setFontSize(13);

  doc.text(
    "Email Threat Analysis Report",
    margin + 72,
    85
  );

  // Start content below header
  y = 125;

  // Email Details
  addSectionHeading("Email Details");

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

  // Verdict and Scoring
  addSectionHeading("Verdict and Scoring");

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

  // Detection Reasons
  addSectionHeading("Detection Reasons");

  result.reasons.forEach(function (reason) {
    addText(
      `• ${reason}`,
      10,
      "normal",
      2
    );
  });

  y += 8;

  // URL Analysis
  addSectionHeading("URL Analysis");

  addText(
    `URLs Detected: ${result.urlMatches.length}`
  );

  addText(
    `Suspicious URLs: ${result.suspiciousUrls.length}`
  );

  if (result.urlMatches.length > 0) {
    result.urlMatches.forEach(function (url) {
      const status = result.suspiciousUrls.includes(url)
        ? "Suspicious"
        : "Not flagged";

      addText(
        `${url} — ${status}`,
        9,
        "normal",
        2
      );
    });
  } else {
    addText("No URLs detected.");
  }

  y += 8;

  // Keyword Analysis
  addSectionHeading("Keyword Analysis");

  addText(
    `Phishing Keywords: ${
      result.matchedPhishing.join(", ") || "None"
    }`
  );

  addText(
    `Spam Keywords: ${
      result.matchedSpam.join(", ") || "None"
    }`
  );

  addText(
    `Urgency Keywords: ${
      result.matchedUrgency.join(", ") || "None"
    }`
  );

  addText(
    `Credential Keywords: ${
      result.matchedCredentials.join(", ") || "None"
    }`
  );

  addText(
    `Possible Brand Indicators: ${
      result.matchedLookalikeBrands.join(", ") || "None"
    }`,
    10,
    "normal",
    12
  );

  // Disclaimer
  addSectionHeading("Disclaimer");

  addText(
    "ClueWell Mail uses client-side keyword and rule-based analysis. The result is an indication only and should not be treated as a guaranteed security decision.",
    9,
    "normal",
    5
  );

  // Footer - Generated Date and Time
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);

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

  // Save PDF
  doc.save("ClueWell-Mail-report.pdf");
}