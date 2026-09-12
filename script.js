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


/* =========================
   ANALYZER EVENT LISTENERS
   ========================= */

if (form) {

  form.addEventListener("submit", function(event) {

    event.preventDefault();

    runAnalysis();

  });

}


if (clearBtn) {

  clearBtn.addEventListener("click", function() {

    if (form) {
      form.reset();
    }

    clearFieldErrors();
    resetResults();

    lastAnalysis = null;

  });

}


if (downloadBtn) {

  downloadBtn.addEventListener("click", function() {

    if (lastAnalysis) {

      generateReport(lastAnalysis);

    }

  });

}

const noteText =
  "Required field For better results, please fill in all available fields.";

const noteElement = document.getElementById("form-note-text");

let noteIndex = 0;

function typeNote() {
  if (noteIndex < noteText.length) {
    noteElement.textContent += noteText.charAt(noteIndex);
    noteIndex++;
    setTimeout(typeNote, 35);
  }
}

typeNote();
/* =========================
   FIELD VALIDATION
   ========================= */

function clearFieldErrors() {

  document.querySelectorAll(".field").forEach(function(field) {

    field.classList.remove("has-error");

  });

}


function setFieldError(fieldId) {

  const field = document.getElementById(fieldId);

  if (field) {

    field.classList.add("has-error");

  }

}


function validateInputs(sender, subject, body) {

  clearFieldErrors();

  let isValid = true;

  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


  // Sender Email - OPTIONAL
  // Validate only when the user enters something.
  if (
    sender.trim() &&
    !emailPattern.test(sender.trim())
  ) {

    setFieldError("field-sender");

    isValid = false;

  }


  // Subject - OPTIONAL
  // No validation required.


  // Email Body - REQUIRED
  if (!body.trim()) {

    setFieldError("field-body");

    isValid = false;

  }


  return isValid;

}


/* =========================
   RUN ANALYSIS
   ========================= */

function runAnalysis() {

  if (!senderInput || !subjectInput || !bodyInput) {
    return;
  }


  const sender = senderInput.value;
  const subject = subjectInput.value;
  const body = bodyInput.value;


  if (!validateInputs(sender, subject, body)) {

    resetResults();

    return;

  }


  const input = {

    senderEmail: sender.trim(),

    subject: subject.trim(),

    body: body.trim()

  };


  const result = analyzeEmail(input);


  lastAnalysis = {

    input: input,

    result: result

  };


  renderResult(input, result);

}


/* =========================
   EMAIL ANALYSIS
   ========================= */

function analyzeEmail(input) {

  const text = (input.subject + " " + input.body)
    .toLowerCase()
    .replace(/\s+/g, " ");


  const phishingKeywords = [

    "verify your account",
    "verify your identity",
    "confirm your identity",
    "confirm your account",
    "verify your details",
    "confirm your details",
    "account verification",
    "security verification",
    "security confirmation",
    "validate your account",
    "validate your identity",
    "unusual activity",
    "suspicious activity",
    "unrecognized login",
    "unrecognized device",
    "unknown device",
    "unknown login",
    "new login detected",
    "new sign-in detected",
    "login attempt",
    "sign-in attempt",
    "security alert",
    "security warning",
    "security notice",
    "security breach",
    "unauthorized access",
    "unauthorized login",
    "account compromised",
    "account has been compromised",
    "account suspended",
    "account suspension",
    "account blocked",
    "account locked",
    "account disabled",
    "access restricted",
    "limited access",
    "restore your account",
    "recover your account",
    "account recovery",
    "reset your password immediately",
    "change your password immediately",
    "password expires",
    "password will expire",
    "password expired",
    "confirm your password",
    "update your password",
    "update your security information",
    "update your billing information",
    "update your payment information",
    "confirm your payment",
    "verify your payment",
    "verify payment method",
    "confirm payment method",
    "verify billing information",
    "confirm billing information",
    "click here to verify",
    "click here to confirm",
    "click the link to verify",
    "click the link to confirm",
    "complete verification",
    "complete the verification",
    "identity verification required",
    "verification required",
    "action required",
    "immediate action required",
    "urgent action required",
    "respond immediately",
    "act immediately",
    "act now",
    "do not ignore",
    "failure to verify",
    "failure to complete verification",
    "within 24 hours",
    "within 48 hours",
    "before your account is suspended",
    "before your account is locked",
    "avoid suspension",
    "avoid account closure"

  ];


  const spamKeywords = [

    "special offer",
    "special offers",
    "limited time offer",
    "limited-time offer",
    "exclusive offer",
    "exclusive deal",
    "mega sale",
    "flash sale",
    "weekend sale",
    "season sale",
    "holiday sale",
    "clearance sale",
    "summer sale",
    "winter sale",
    "festive sale",
    "big sale",
    "huge sale",
    "massive sale",
    "discount",
    "discounts",
    "save big",
    "save more",
    "save up to",
    "best price",
    "best prices",
    "lowest price",
    "special price",
    "special prices",
    "great deal",
    "great deals",
    "amazing deal",
    "amazing deals",
    "hot deal",
    "hot deals",
    "exclusive deal",
    "exclusive deals",
    "limited offer",
    "limited offers",
    "offer ends",
    "offer expires",
    "offer valid",
    "offer valid until",
    "buy now",
    "shop now",
    "order now",
    "book now",
    "grab now",
    "get yours now",
    "don't miss",
    "dont miss",
    "don't miss out",
    "dont miss out",
    "free shipping",
    "free delivery",
    "free gift",
    "free trial",
    "gift voucher",
    "gift card",
    "coupon",
    "coupon code",
    "promo code",
    "promotion",
    "promotional",
    "promotional offer",
    "cashback",
    "cash back",
    "reward points",
    "bonus points",
    "membership offer",
    "loyalty offer",
    "new collection",
    "new arrivals",
    "shop our collection",
    "browse our deals",
    "browse our offers",
    "online shopping",
    "shopping deal",
    "shopping deals",
    "price drop",
    "prices dropped",
    "exclusive access",
    "member exclusive",
    "members only",
    "early access",
    "special promotion",
    "limited stock",
    "while supplies last",
    "today only",
    "this weekend only"

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
    "time-sensitive",
    "immediate response"

  ];


  const credentialKeywords = [

    "login credentials",
    "account credentials",
    "username and password",
    "enter your password",
    "provide your password",
    "confirm your password",
    "enter your login",
    "enter your credentials",
    "security code",
    "verification code",
    "authentication code",
    "one-time password",
    "one time password"

  ];


  const lookalikeBrands = [

    "paypal",
    "paypa1",
    "paypaI",
    "paypai",
    "microsoft",
    "micros0ft",
    "micr0soft",
    "micro5oft",
    "amaz0n",
    "arnazon",
    "amazom",
    "amazon",
    "netflix",
    "netfl1x",
    "netfIix",
    "netfiix",
    "apple",
    "app1e",
    "appIe",
    "app1e-id",
    "google",
    "g00gle",
    "goog1e",
    "go0gle",
    "facebook",
    "faceb00k",
    "facebo0k",
    "instagram",
    "instagr4m",
    "instagran",
    "linkedin",
    "linkedln",
    "linkedi n",
    "github",
    "githab",
    "g1thub",
    "git-hub",
    "adobe",
    "ad0be",
    "adob3",
    "dropbox",
    "dropb0x",
    "docusign",
    "d0cusign",
    "steam",
    "ste4m",
    "spotify",
    "spot1fy",
    "whatsapp",
    "whats4pp",
    "telegram",
    "te1egram",
    "coinbase",
    "c0inbase",
    "binance",
    "b1nance",
    "ebay",
    "eb4y",
    "walmart",
    "w4lmart",
    "target",
    "t4rget",
    "bestbuy",
    "bestbu y",
    "samsung",
    "samsun9",
    "samsung-support",
    "hp",
    "h0",
    "dell",
    "de11",
    "lenovo",
    "len0vo",
    "intel",
    "inte1",
    "nvidia",
    "nvid1a",
    "zoom",
    "z00m",
    "slack",
    "s1ack",
    "discord",
    "disc0rd",
    "notion",
    "n0tion",
    "canva",
    "canv4",
    "coursera",
    "courser4",
    "netbanking",
    "paytm",
    "payt m",
    "phonepe",
    "phonep3",
    "razorpay",
    "raz0rpay",
    "hdfc",
    "hdfcbank",
    "icicibank",
    "sbi",
    "onlinesbi",
    "axisbank",
    "bankofamerica",
    "chase",
    "americanexpress",
    "amex"

  ];


  const matchedPhishing = phishingKeywords.filter(function(keyword) {

    return text.includes(keyword);

  });


  const matchedSpam = spamKeywords.filter(function(keyword) {

    return text.includes(keyword);

  });


  const matchedUrgency = urgencyKeywords.filter(function(keyword) {

    return text.includes(keyword);

  });


  const matchedCredentials = credentialKeywords.filter(function(keyword) {

    return text.includes(keyword);

  });


  const urlMatches =
    input.body.match(/https?:\/\/[^\s)>"']+/gi) || [];


  const suspiciousUrls = urlMatches.filter(function(url) {

    try {

      const hostname = new URL(url).hostname.toLowerCase();


      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {

        return true;

      }


      if (hostname.includes("xn--")) {

        return true;

      }


      if (
        hostname.includes("verify-") ||
        hostname.includes("-verify") ||
        hostname.includes("secure-") ||
        hostname.includes("-secure") ||
        hostname.includes("account-") ||
        hostname.includes("-account") ||
        hostname.includes("login-") ||
        hostname.includes("-login")
      ) {

        return true;

      }


      return false;

    } catch {

      return true;

    }

  });


  const senderLower = input.senderEmail.toLowerCase();

  let senderDomain = "";


  try {

    senderDomain = senderLower.split("@")[1] || "";

  } catch {

    senderDomain = "";

  }


  const matchedLookalikeBrands = lookalikeBrands.filter(function(brand) {

    return senderDomain.includes(brand.toLowerCase());

  });


  const senderLooksOff =
    /\d{4,}/.test(senderLower) ||
    senderLower.includes("-verify") ||
    senderLower.includes("verify-") ||
    senderLower.includes("-secure") ||
    senderLower.includes("secure-") ||
    senderLower.includes("-account") ||
    senderLower.includes("account-") ||
    senderLower.includes("-login") ||
    senderLower.includes("login-");


  let phishingScore = 0;

  let spamScore = 0;


  phishingScore += matchedPhishing.length * 15;

  phishingScore += suspiciousUrls.length * 20;


  if (senderLooksOff) {

    phishingScore += 15;

  }


  if (matchedLookalikeBrands.length > 0) {

    phishingScore += 30;

  }


  if (matchedUrgency.length > 0) {

    phishingScore += 8;

  }


  if (matchedCredentials.length > 0) {

    phishingScore += 8;

  }


  const hasVerification =
    text.includes("verify") ||
    text.includes("verification") ||
    text.includes("confirm your identity") ||
    text.includes("confirm your account");


  const hasThreat =
    text.includes("suspended") ||
    text.includes("blocked") ||
    text.includes("locked") ||
    text.includes("restricted") ||
    text.includes("terminated") ||
    text.includes("closure");


  if (hasVerification && hasUrgency(text)) {

    phishingScore += 20;

  }


  if (hasVerification && hasThreat) {

    phishingScore += 20;

  }


  spamScore += matchedSpam.length * 7;


  if (matchedSpam.length >= 2) {

    spamScore += 10;

  }


  if (
    text.includes("offer") &&
    (
      text.includes("shop") ||
      text.includes("sale") ||
      text.includes("discount") ||
      text.includes("deal")
    )
  ) {

    spamScore += 15;

  }


  if (
    text.includes("buy now") ||
    text.includes("shop now") ||
    text.includes("subscribe") ||
    text.includes("coupon code") ||
    text.includes("promo code")
  ) {

    spamScore += 10;

  }


  phishingScore = Math.min(phishingScore, 97);

  spamScore = Math.min(spamScore, 95);


  let verdict = "legitimate";

  let riskScore = 8;

  let confidence = 80;


  if (phishingScore >= 50) {

    verdict = "phishing";

    riskScore = phishingScore;

    confidence = Math.min(
      85 + matchedPhishing.length * 2 + matchedLookalikeBrands.length * 2,
      99
    );

  } else if (spamScore >= 30) {

    verdict = "spam";

    riskScore = Math.min(20 + spamScore, 95);

    confidence = Math.min(
      82 + matchedSpam.length * 2,
      97
    );

  } else {

    verdict = "legitimate";

    riskScore = Math.min(
      8 + phishingScore + Math.floor(spamScore / 2),
      49
    );

    confidence = Math.max(
      85 - Math.floor(riskScore / 5),
      65
    );

  }


  const reasons = [];


  if (verdict === "phishing") {

    if (matchedPhishing.length > 0) {

      reasons.push(
        "Suspicious account or security language detected"
      );

    }


    if (suspiciousUrls.length > 0) {

      reasons.push(
        "Suspicious URL pattern detected"
      );

    }


    if (senderLooksOff) {

      reasons.push(
        "Sender address contains a suspicious pattern"
      );

    }


    if (matchedLookalikeBrands.length > 0) {

      reasons.push(
        "Lookalike or impersonation brand detected in sender domain"
      );

    }


    if (hasVerification && matchedUrgency.length > 0) {

      reasons.push(
        "Verification language combined with urgency"
      );

    }


    if (hasVerification && hasThreat) {

      reasons.push(
        "Account verification combined with an account threat"
      );

    }

  } else if (verdict === "spam") {

    reasons.push(
      "Promotional or marketing language detected"
    );


    if (matchedSpam.length >= 2) {

      reasons.push(
        "Multiple promotional keywords detected"
      );

    }


    if (
      text.includes("offer") ||
      text.includes("sale") ||
      text.includes("discount") ||
      text.includes("deal")
    ) {

      reasons.push(
        "Commercial offer or sales language detected"
      );

    }

  } else {

    reasons.push(
      "No strong phishing or spam indicators found"
    );

  }


  const keywordResults = [

    ...matchedPhishing.map(function(keyword) {

      return {
        term: keyword,
        type: "phishing"
      };

    }),

    ...matchedSpam.map(function(keyword) {

      return {
        term: keyword,
        type: "spam"
      };

    })

  ];


  return {

    verdict: verdict,

    riskScore: Math.round(riskScore),

    confidence: Math.round(confidence),

    reasons: reasons,

    urls: {

      detected: urlMatches.length,

      suspicious: suspiciousUrls.length

    },

    keywords: keywordResults

  };

}


/* =========================
   URGENCY CHECK
   ========================= */

function hasUrgency(text) {

  return (
    text.includes("urgent") ||
    text.includes("immediately") ||
    text.includes("act now") ||
    text.includes("action required") ||
    text.includes("within 24 hours") ||
    text.includes("within 48 hours")
  );

}


/* =========================
   RESET RESULTS
   ========================= */

function resetResults() {

  if (!resultEmpty || !resultContent || !verdictRow) {
    return;
  }


  resultEmpty.classList.remove("is-hidden");

  resultContent.classList.remove("is-visible");

  verdictRow.classList.remove(
    "phishing",
    "spam",
    "legitimate"
  );

}


/* =========================
   RENDER RESULT
   ========================= */

function renderResult(input, result) {

  if (
    !resultEmpty ||
    !resultContent ||
    !verdictRow ||
    !verdictValue ||
    !riskScoreEl ||
    !confidenceScoreEl ||
    !reasonList ||
    !urlsDetectedEl ||
    !urlsSuspiciousEl ||
    !keywordList
  ) {

    return;

  }


  resultEmpty.classList.add("is-hidden");

  resultContent.classList.add("is-visible");


  verdictRow.classList.remove(
    "phishing",
    "spam",
    "legitimate"
  );


  verdictRow.classList.add(result.verdict);


  if (result.verdict === "phishing") {

    verdictValue.textContent = "PHISHING";

  } else if (result.verdict === "spam") {

    verdictValue.textContent = "SPAM";

  } else {

    verdictValue.textContent = "LEGITIMATE";

  }


  riskScoreEl.textContent =
    result.riskScore + "%";


  confidenceScoreEl.textContent =
    result.confidence + "%";


  reasonList.innerHTML = "";


  result.reasons.forEach(function(reason) {

    const li = document.createElement("li");

    li.textContent = reason;

    reasonList.appendChild(li);

  });


  urlsDetectedEl.textContent =
    result.urls.detected;


  urlsSuspiciousEl.textContent =
    result.urls.suspicious;


  keywordList.innerHTML = "";


  if (result.keywords.length === 0) {

    const span = document.createElement("span");

    span.className = "keyword-chip";

    span.textContent =
      "No suspicious keywords found";

    keywordList.appendChild(span);

  } else {

    result.keywords.forEach(function(keyword) {

      const span = document.createElement("span");

      span.className =
        "keyword-chip flagged " +
        (keyword.type === "spam" ? "spam" : "phishing");

      span.textContent = keyword.term;

      keywordList.appendChild(span);

    });

  }

}


/* =========================
   PDF REPORT
   ========================= */

async function generateReport(analysis) {

  if (!window.jspdf) {
    return;
  }


  const { jsPDF } = window.jspdf;


  const doc = new jsPDF({

    unit: "pt",

    format: "a4"

  });


  const marginX = 48;

  let y = 56;

  const lineHeight = 16;

  const pageWidth =
    doc.internal.pageSize.getWidth();

  const contentWidth =
    pageWidth - marginX * 2;


  function addLine(text, size, style) {

    doc.setFontSize(size || 11);

    doc.setFont(
      "helvetica",
      style || "normal"
    );


    const wrapped =
      doc.splitTextToSize(
        String(text),
        contentWidth
      );


    wrapped.forEach(function(line) {

      if (y > 780) {

        doc.addPage();

        y = 56;

      }


      doc.text(
        line,
        marginX,
        y
      );


      y += lineHeight;

    });

  }


  function addSpacer(amount) {

    y += amount || 8;

  }


  /* Logo */

  const logo = new Image();

  logo.src = "phishnet-report-logo.png";


  await new Promise(function(resolve) {

    logo.onload = resolve;

    logo.onerror = resolve;

  });


  if (
    logo.complete &&
    logo.naturalWidth > 0
  ) {

    doc.addImage(
      logo,
      "PNG",
      marginX,
      y - 24,
      42,
      42
    );

  }


  /* Header */

  doc.setFontSize(16);

  doc.setFont(
    "helvetica",
    "bold"
  );


  doc.text(
    "PhishNet AI",
    marginX + 44,
    y
  );


  addSpacer(28);


  addLine(
    "Email Threat Analysis Report",
    13,
    "bold"
  );


  addSpacer(4);


  const now = new Date();


  addLine(
    "Generated: " +
    now.toLocaleString(),
    10
  );


  addSpacer(10);


  addLine(
    "Email Details",
    12,
    "bold"
  );


  addLine(
    "Sender: " +
    (analysis.input.senderEmail || "(not provided)")
  );


  addLine(
    "Subject: " +
    (analysis.input.subject || "(not provided)")
  );


  addSpacer(4);


  addLine(
    "Body:",
    11,
    "bold"
  );


  addLine(
    analysis.input.body ||
    "(empty)"
  );


  addSpacer(10);


  addLine(
    "Verdict and Scoring",
    12,
    "bold"
  );


  let reportVerdict =
    "LEGITIMATE";


  if (
    analysis.result.verdict ===
    "phishing"
  ) {

    reportVerdict =
      "PHISHING";

  } else if (
    analysis.result.verdict ===
    "spam"
  ) {

    reportVerdict =
      "SPAM";

  }


  addLine(
    "Verdict: " +
    reportVerdict
  );


  addLine(
    "Risk Score: " +
    analysis.result.riskScore +
    "%"
  );


  addLine(
    "Confidence: " +
    analysis.result.confidence +
    "%"
  );


  addSpacer(10);


  addLine(
    "Detection Reasons",
    12,
    "bold"
  );


  analysis.result.reasons.forEach(
    function(reason) {

      addLine(
        "- " + reason
      );

    }
  );


  addSpacer(10);


  addLine(
    "URL Analysis",
    12,
    "bold"
  );


  addLine(
    "URLs detected: " +
    analysis.result.urls.detected
  );


  addLine(
    "Suspicious URLs: " +
    analysis.result.urls.suspicious
  );


  addSpacer(10);


  addLine(
    "Keyword Analysis",
    12,
    "bold"
  );


  if (
    analysis.result.keywords.length === 0
  ) {

    addLine(
      "No suspicious keywords found."
    );

  } else {

    addLine(
      analysis.result.keywords
        .map(function(keyword) {

          return keyword.term;

        })
        .join(", ")
    );

  }


  addSpacer(16);


  addLine(
    "Disclaimer",
    12,
    "bold"
  );


  addLine(
    "This result is an automated assessment and should not be treated as definitive proof that an email is malicious, spam, or legitimate.",
    10
  );


  doc.save(
    "phishnet-ai-report.pdf"
  );

}


/* =========================
   MOBILE NAVIGATION
   ========================= */

const navToggle =
  document.querySelector(".nav-toggle");

const navLinks =
  document.querySelector(".nav-links");


if (navToggle && navLinks) {

  navToggle.addEventListener(
    "click",
    function() {

      const isOpen =
        navLinks.classList.toggle(
          "is-open"
        );


      navToggle.setAttribute(
        "aria-expanded",
        String(isOpen)
      );

    }
  );


  navLinks
    .querySelectorAll("a")
    .forEach(function(link) {

      link.addEventListener(
        "click",
        function() {

          navLinks.classList.remove(
            "is-open"
          );


          navToggle.setAttribute(
            "aria-expanded",
            "false"
          );

        }
      );

    });

}