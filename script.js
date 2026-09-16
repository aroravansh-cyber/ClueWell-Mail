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

const phishingKeywords = [
  "verify your account",
  "verify account",
  "confirm your account",
  "confirm your identity",
  "complete verification",
  "security alert",
  "security notice",
  "unusual activity",
  "suspicious activity",
  "unrecognized login",
  "unrecognized device",
  "unauthorized access",
  "account suspended",
  "account locked",
  "account blocked",
  "account restricted",
  "account terminated",
  "action required",
  "immediate action",
  "update your information",
  "update payment information",
  "verify payment",
  "confirm payment",
  "reset your password",
  "password expires",
  "login attempt",
  "secure your account",
  "security verification",
  "identity verification",
  "account recovery",
  "click here to verify",
  "your account will be closed",
  "your account will be deleted",
  "failure to verify",
  "complete the process",
  "within 24 hours",
  "within 48 hours"
];
const spamKeywords = [
  "exclusive offer",
  "special offer",
  "limited offer",
  "amazing offer",
  "special promotion",
  "exclusive promotion",
  "great offer",
  "best offer",
  "discount",
  "big discount",
  "huge discount",
  "massive discount",
  "special discount",
  "instant discount",
  "extra discount",
  "free gift",
  "free sample",
  "free trial",
  "free bonus",
  "free reward",
  "claim your prize",
  "claim your reward",
  "claim now",
  "claim your gift",
  "you have won",
  "you are a winner",
  "winner",
  "winning prize",
  "congratulations",
  "congratulations winner",
  "lucky winner",
  "lucky draw",
  "prize winner",
  "cash prize",
  "cash reward",
  "bonus reward",
  "special reward",
  "buy now",
  "shop now",
  "order now",
  "subscribe now",
  "sign up now",
  "join now",
  "limited time",
  "limited time offer",
  "last chance",
  "hurry",
  "hurry up",
  "act fast",
  "don't miss out",
  "offer expires",
  "offer ends soon",
  "expires today",
  "limited stock",
  "while supplies last",
  "huge savings",
  "big savings",
  "save big",
  "save money",
  "best deal",
  "great deal",
  "deal of the day",
  "exclusive deal",
  "special deal",
  "flash sale",
  "mega sale",
  "super sale",
  "clearance sale",
  "season sale",
  "holiday sale",
  "promo code",
  "promotional code",
  "coupon code",
  "discount code",
  "voucher",
  "gift voucher",
  "cashback",
  "cash back",
  "bonus",
  "welcome bonus",
  "instant bonus",
  "special bonus",
  "member bonus",
  "reward points",
  "bonus points",
  "free money",
  "easy money",
  "make money",
  "make money fast",
  "earn money",
  "earn extra income",
  "extra income",
  "work from home",
  "home based job",
  "online job",
  "easy income",
  "get rich",
  "get rich quick",
  "money making opportunity",
  "business opportunity",
  "investment opportunity",
  "guaranteed income",
  "guaranteed returns",
  "risk free",
  "no risk",
  "no investment",
  "zero investment",
  "cheap price",
  "lowest price",
  "best price",
  "special price",
  "free shipping",
  "free delivery",
  "free membership",
  "free upgrade",
  "upgrade now",
  "renew now",
  "apply now",
  "register now",
  "click here",
  "click now",
  "learn more",
  "don't miss this",
  "one time offer",
  "today only",
  "offer available",
  "exclusive access",
  "special access",
  "limited availability",
  "act today"
];
const urgencyKeywords = [
  "urgent",
  "immediately",
  "act now",
  "action required",
  "final warning",
  "last chance",
  "expires today",
  "respond immediately",
  "within 24 hours",
  "within 48 hours",
  "do not delay",
  "time sensitive",
  "immediate response",
  "as soon as possible"
];

const credentialKeywords = [
  "login credentials",
  "account credentials",
  "username and password",
  "enter your password",
  "provide your password",
  "securifty code",
  "verification code",
  "authentication code",
  "one time password",
  "otp",
  "pin",
  "credit card number",
  "debit card number",
  "bank account details",
  "cvv",
  "card details"
];

const brandVariants = [
  "paypa1",
  "pay-pal",
  "micros0ft",
  "micro-soft",
  "amaz0n",
  "amaz-on",
  "g00gle",
  "faceb00k",
  "app1e",
  "netfl1x",
  "linkedln",
  "dell-support",
  "bank-security",
  "secure-paypal",
  "microsoft-security",
  "amazon-security"
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