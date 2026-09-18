/* =========================================================

 ClueWell Mail - ENHANCED

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

 KEYWORD SEVERITY SYSTEM

 ========================================================= */



// Critical keywords (weight: 9) - Strongest phishing indicators

const criticalPhishingKeywords = [

 "verify your account now", "confirm your account now", "validate your account now",

 "your account will be closed", "your account will be suspended", "your account will be deleted",

 "click here to verify immediately", "click the link to confirm", "verify using the link",

 "account has been compromised", "unauthorized access detected", "suspicious login blocked",

 "within 24 hours or", "before your account expires", "before access is permanently blocked",

 "re-enter your password", "submit your password below", "provide your login credentials",

 "confirm credit card number", "verify banking details", "authenticate payment method",

 "account security compromised", "suspicious activity on your account", "unauthorized transactions"

];



// High-risk keywords (weight: 7) - Strong phishing signals

const highPhishingKeywords = [

 "verify your identity", "confirm your identity", "validate your account", "authenticate account",

 "security alert", "security notice", "security warning", "critical alert",

 "account locked", "account suspended", "account restricted", "account disabled",

 "unusual activity", "suspicious activity", "unrecognized login", "unauthorized access",

 "immediate action required", "urgent action required", "critical action",

 "update your password", "reset your password", "change your password",

 "action required immediately", "response required today", "confirm your information"

];



// Medium-risk keywords (weight: 5) - Moderate phishing indicators

const mediumPhishingKeywords = [

 "account verification", "account authentication", "security verification", "verify account",

 "security update required", "verification code", "confirmation code",

 "new device detected", "new location login", "recent login attempt",

 "complete verification", "finish authentication", "verify using link",

 "banking information", "payment information", "billing details",

 "confirm your details", "update account information"

];



// Crypto & blockchain scams (weight: 8)

const cryptoScamKeywords = [

 "bitcoin", "ethereum", "cryptocurrency", "crypto wallet", "blockchain", "defi", "nft",

 "crypto exchange", "metamask", "coinbase", "bitcoin wallet", "ethereum address",

 "claim your crypto", "pending deposit", "withdraw coins", "unlock crypto",

 "crypto investment opportunity", "guaranteed crypto returns", "passive crypto income",

 "private key", "seed phrase", "wallet recovery", "crypto holdings"

];



// Tax/IRS/Government impersonation (weight: 8)

const taxScamKeywords = [

 "irs alert", "irs notice", "tax refund pending", "tax return", "tax audit",

 "back taxes owed", "tax penalty", "federal tax", "tax compliance",

 "verify tax information", "confirm tax status", "tax verification required",

 "immediate tax payment required", "urgent tax payment", "overdue taxes",

 "internal revenue service", "government compliance", "penalty notice"

];



// Banking/Financial impersonation (weight: 8)

const bankingScamKeywords = [

 "bank account verification", "banking credentials", "bank security alert",

 "account number verification", "account holder verification", "bank details",

 "wire transfer verification", "bank transfer pending", "payment processing",

 "confirm banking information", "verify bank account", "banking security update",

 "access to your account", "banking compliance", "account suspension"

];



// Social engineering & manipulation (weight: 6)

const socialEngineeringKeywords = [

 "act now", "act today", "act immediately", "do not delay", "without delay",

 "limited time offer", "last chance", "final opportunity", "one-time offer",

 "exclusive offer", "special deal", "urgent deal", "today only",

 "claim your reward", "claim your prize", "you won", "congratulations",

 "limited slots available", "limited access", "members only"

];



// Original PHISHING keywords (comprehensive list)

const phishingKeywords=[

"verify your account","verify account","verify my account","verify the account","confirm your account","confirm account","confirm my account","confirm the account","validate your account","validate account","authenticate your account","authenticate account","activate your account","reactivate your account","restore your account",

"verify your identity","verify identity","confirm your identity","confirm identity","validate your identity","validate identity","authenticate your identity","authenticate identity","identity verification","identity confirmation","identity validation","identity authentication","identity check","identity verification required","identity confirmation required",

"complete verification","complete the verification","complete account verification","complete identity verification","complete security verification","complete authentication","complete the authentication","finish verification","finish the verification","finish account verification","finish identity verification","verification required","verification is required","verification needed","verification is needed",

"security alert","security notice","security warning","security notification","security message","security update","security incident","security issue","security concern","security problem","security check","security verification","security confirmation","security validation","security authentication","security review","security assessment","security action required",

"unusual activity","unusual account activity","unusual login activity","unusual sign in activity","unusual sign-in activity","unusual transaction","unusual transaction activity","unusual payment activity","unusual access","unusual behavior","unusual behavior detected","unusual activity detected","unusual login detected","unusual sign in detected","unusual access detected",

"suspicious activity","suspicious account activity","suspicious login activity","suspicious sign in activity","suspicious sign-in activity","suspicious transaction","suspicious transaction activity","suspicious payment","suspicious payment activity","suspicious access","suspicious behavior","suspicious activity detected","suspicious login detected","suspicious access detected","suspicious transaction detected",

"unrecognized login","unrecognized sign in","unrecognized sign-in","unrecognized login attempt","unrecognized sign in attempt","unrecognized device","unrecognized device detected","unrecognized browser","unrecognized location","unrecognized location detected","unrecognized session","unrecognized access","unrecognized activity","unrecognized transaction","unrecognized payment"

];



// Spam keywords

const spamKeywords=[

"exclusive offer","special offer","limited offer","amazing offer","incredible offer","fantastic offer","unbeatable offer","exclusive deal","special deal","great deal","best deal","mega deal","super deal","hot deal","daily deal","deal of the day","deal of the week","deal of the month",

"special promotion","exclusive promotion","limited promotion","seasonal promotion","holiday promotion","promotional offer","promotional deal","promotional event","special campaign","exclusive campaign","member offer","member promotion","member deal","customer offer","customer promotion","customer reward","loyalty offer","loyalty reward","loyalty bonus",

"discount","big discount","huge discount","massive discount","major discount","special discount","exclusive discount","limited discount","instant discount","extra discount","additional discount","maximum discount","flat discount","special savings","huge savings","big savings","massive savings","great savings","save big","save money","save more",

"free gift","free sample","free trial","free bonus","free reward","free prize","free voucher","free coupon","free product","free item","free membership","free subscription","free upgrade","free delivery","free shipping","free service","free access","free entry","free consultation","free registration",

"claim your prize","claim your reward","claim your gift","claim your bonus","claim your voucher","claim your coupon","claim your offer","claim your discount","claim your cashback","claim your free gift","claim now","claim today","claim immediately","claim your reward now","claim your prize now","claim your gift now","redeem now","redeem your reward","redeem your voucher","redeem your coupon",

"you have won","you are a winner","you are selected","you have been selected","winner","winning prize","winning reward","prize winner","lucky winner","lucky customer","lucky member","lucky draw","lucky prize","cash prize","cash reward","cash bonus","special reward","bonus reward","exclusive reward","instant reward",

"congratulations","congratulations winner","congratulations you won","congratulations you are selected","congratulations customer","congratulations member","congratulations lucky winner","you won","you won a prize","you won a reward","you won a gift","you won cash","you won cashback","you have won a prize","you have won a reward","you have won a gift","your prize is ready","your reward is ready","your gift is waiting",

"buy now","shop now","order now","purchase now","subscribe now","sign up now","join now","register now","apply now","book now","reserve now","get yours now","grab yours now","get it now","shop today","order today","buy today","purchase today","start today","join today",

"limited time","limited time offer","limited time deal","limited time discount","limited time promotion","limited availability","limited stock","limited quantity","limited seats","limited entries","limited membership","limited access","limited supply","while supplies last","while stocks last","while stock lasts","only today","today only","this week only","available today",

"last chance","last opportunity","final chance","final opportunity","hurry","hurry up","act fast","act today","act now","don't miss out","dont miss out","don't miss this","dont miss this","don't miss your chance","dont miss your chance","don't wait","dont wait","offer expires","offer ends soon","offer ending soon",

"expires today","expire today","expires soon","expiring soon","expiration today","deadline today","due today","due immediately","deadline approaching","deadline is approaching","approaching deadline","short deadline","limited time","limited timeframe","limited window","limited period","time sensitive","time-sensitive","time critical","time-critical",

"huge savings","big savings","massive savings","save big","save money","save more","save up to","save upto","up to 50 percent off","up to 70 percent off","up to 80 percent off","up to 90 percent off","50 percent off","60 percent off","70 percent off","80 percent off","90 percent off","half price","half off","price drop",

"best price","lowest price","cheap price","special price","exclusive price","discounted price","reduced price","sale price","special pricing","member price","member pricing","customer pricing","early bird price","introductory price","special rate","lowest rate","best rate","exclusive rate","reduced rate","limited price",

"promo code","promotional code","promotion code","coupon code","discount code","offer code","voucher code","gift code","reward code","cashback code","referral code","special code","exclusive code","member code","customer code","redeem code","promo voucher","discount voucher","gift voucher","shopping voucher",

"voucher","gift voucher","shopping voucher","discount voucher","cashback","cash back","instant cashback","extra cashback","cashback offer","cashback reward","cashback bonus","cashback deal","cashback available","earn cashback","get cashback","receive cashback","bonus","welcome bonus","instant bonus","special bonus","member bonus","customer bonus","signup bonus","sign up bonus","referral bonus","deposit bonus",

"reward points","bonus points","loyalty points","membership points","customer points","bonus reward","reward bonus","reward offer","loyalty reward","member reward","customer reward","redeem points","redeem rewards","earn points","earn rewards","double points","triple points","extra points","bonus points available","points promotion",

"free money","easy money","make money","make money fast","make money online","earn money","earn money online","earn extra income","extra income","passive income","online income","easy income","quick income","fast income","additional income","monthly income","weekly income","daily income","instant income","guaranteed income",

"work from home","work from home opportunity","home based job","home based work","online job","online work","remote job opportunity","remote work opportunity","part time job","part time work","full time opportunity","easy job","easy work","easy income","flexible job","flexible work","earn from home","earn while you sleep","work online","job opportunity"

];



// Urgency keywords

const urgencyKeywords=[

"urgent","urgently","immediately","immediate action","act now","act immediately","take action now","action required","action needed","action requested","action must be taken","response required","response needed","reply required","reply immediately","respond immediately","respond now","respond today","respond as soon as possible","respond without delay",

"final warning","final notice","final alert","final reminder","last warning","last notice","last reminder","last chance","final opportunity","last opportunity","urgent notice","urgent alert","urgent request","urgent action","urgent response","urgent verification","urgent confirmation","urgent attention",

"expires today","expire today","expires soon","expiring soon","expiration today","deadline today","due today","due immediately","deadline approaching","deadline is approaching","approaching deadline","short deadline","limited time","limited timeframe","limited window","limited period","time sensitive","time-sensitive","time critical","time-critical",

"immediate response","immediate attention","immediate verification","immediate confirmation","immediate action required","immediate attention required","immediate response required","immediate verification required","immediate confirmation required","immediate payment required","immediate update required","immediate login required","immediate account action",

"within 24 hours","within 48 hours","within 12 hours","within 6 hours","within 2 hours","within 1 hour","within one hour","within two hours","within six hours","within twelve hours","within twenty four hours","within twenty-four hours","within forty eight hours","within forty-eight hours","before 24 hours","before 48 hours"

];



// Credential keywords

const credentialKeywords=[

"login credentials","account credentials","user credentials","user login","login details","account login details","login information","account information","login data","account login","login authentication","account authentication","user authentication","login verification","account verification",

"username","user name","user id","userid","login id","login username","account username","account user id","user identification","login identity","account identity","member id","customer id","client id","employee id",

"username and password","username/password","user id and password","user id/password","login id and password","login id/password","account id and password","account username and password","user name and password","user name/password","email and password","email/password","login name and password","login credentials required","credentials required",

"enter your username","enter username","enter your user id","enter user id","enter your login id","enter login id","enter your account id","enter account id","enter your login name","enter login name","provide your username","provide username","provide your user id","provide user id","provide your login id","provide login id",

"password","account password","login password","user password","current password","old password","new password","temporary password","one time password","one-time password","one time passcode","one-time passcode","temporary login password","temporary access password","account login password","user login password","online password","portal password","service password","member password",

"enter your password","enter password","enter the password","enter your account password","enter account password","enter your login password","enter login password","provide your password","provide password","provide the password","provide your account password","submit your password","submit password","submit the password","submit your account password","confirm your password","confirm password","confirm the password","confirm your account password","verify your password",

"security code","verification code","auth code","otp","one-time code","access token","api key","private key","secret key","encryption key"

];



// Lookalike brand keywords

const lookalikeBrands = [

 "paypa1", "paypa", "paypal", "apple id", "icloud", "amazon", "microsoft",

 "google", "facebook", "whatsapp", "instagram", "twitter", "linkedin", "reddit",

 "bank of america", "citibank", "wells fargo", "chase", "boa", "hsbc",

 "visa", "mastercard", "american express", "discover", "payoneer",

 "uber", "lyft", "airbnb", "booking", "netflix", "spotify"

];






/* =========================================================

 FORM HANDLING & INITIALIZATION

 ========================================================= */



if (form) {

 form.addEventListener("submit", function (e) {

  e.preventDefault();

  runAnalysis();

 });

}



function clearForm() {

 if (senderInput) senderInput.value = "";

 if (subjectInput) subjectInput.value = "";

 if (bodyInput) bodyInput.value = "";



 clearFieldErrors();



 if (resultEmpty) {

  resultEmpty.style.display = "block";

 }



 if (resultContent) {

  resultContent.style.display = "none";

 }

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

 ENHANCED ANALYSIS WITH WEIGHTED SCORING

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

  const result = analyzeEmail({ sender, subject, body });
  lastAnalysis = result;
  renderResults(result);
}


function analyzeEmail(input) {
  const sender = input?.sender?.trim() || "";
  const subject = input?.subject?.trim() || "";
  const body = input?.body?.trim() || "";

  // Normalize once for faster and more consistent matching.
  const lowerText = `${subject} ${body}`
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();

  // Keyword matching
  const criticalPhishingMatches = findMatches(lowerText, criticalPhishingKeywords);
  const highPhishingMatches = findMatches(lowerText, highPhishingKeywords);
  const mediumPhishingMatches = findMatches(lowerText, mediumPhishingKeywords);
  const cryptoMatches = findMatches(lowerText, cryptoScamKeywords);
  const taxMatches = findMatches(lowerText, taxScamKeywords);
  const bankingMatches = findMatches(lowerText, bankingScamKeywords);
  const matchedSpam = findMatches(lowerText, spamKeywords);
  const matchedUrgency = findMatches(lowerText, urgencyKeywords);
  const matchedCredentials = findMatches(lowerText, credentialKeywords);
  const matchedSocialEng = findMatches(lowerText, socialEngineeringKeywords);
  const matchedLookalikeBrands = findMatches(lowerText, lookalikeBrands);

  const matchedPhishing = [...new Set([
    ...criticalPhishingMatches,
    ...highPhishingMatches,
    ...mediumPhishingMatches,
    ...cryptoMatches,
    ...taxMatches,
    ...bankingMatches,
    ...matchedCredentials,
    ...matchedLookalikeBrands
  ])];

  // Correct URL extraction.
  const urlMatches = lowerText.match(/https?:\/\/[^\s<>"']+/gi) || [];
  const suspiciousUrls = urlMatches.filter(isSuspiciousUrl);

  const senderLooksOff = sender ? isUnusualSender(sender) : false;
  const senderDomain = sender ? getSenderDomain(sender) : "Unknown";

  // ==========================================
  // WEIGHTED PHISHING SCORE
  // ==========================================
  let phishingScore = 0;

  // Category caps prevent repeated/overlapping phrases
  // from artificially inflating the score.
  phishingScore += Math.min(27, criticalPhishingMatches.length * 9);
  phishingScore += Math.min(21, highPhishingMatches.length * 7);
  phishingScore += Math.min(15, mediumPhishingMatches.length * 5);

  phishingScore += Math.min(12, cryptoMatches.length * 6);
  phishingScore += Math.min(12, taxMatches.length * 6);
  phishingScore += Math.min(12, bankingMatches.length * 6);

  // Generic credential words are deliberately capped.
  phishingScore += Math.min(18, matchedCredentials.length * 4);

  phishingScore += Math.min(20, suspiciousUrls.length * 10);

  if (senderLooksOff) {
    phishingScore += 12;
  }

  phishingScore += Math.min(16, matchedLookalikeBrands.length * 8);

  // Urgency is supporting evidence, not a standalone phishing trigger.
  phishingScore += Math.min(12, matchedUrgency.length * 3);

  // ==========================================
  // COMBINATION BONUSES
  // ==========================================

  if (matchedPhishing.length > 0 && matchedUrgency.length > 0) {
    phishingScore += 8;
  }

  if (matchedCredentials.length > 0 && matchedUrgency.length > 0) {
    phishingScore += 8;
  }

  if (matchedCredentials.length > 0 && suspiciousUrls.length > 0) {
    phishingScore += 12;
  }

  if (matchedLookalikeBrands.length > 0 && suspiciousUrls.length > 0) {
    phishingScore += 10;
  }

  if (senderLooksOff && suspiciousUrls.length > 0) {
    phishingScore += 8;
  }

  if (bankingMatches.length > 0 && matchedCredentials.length > 0) {
    phishingScore += 10;
  }

  if (cryptoMatches.length > 0 && matchedCredentials.length > 0) {
    phishingScore += 10;
  }

  if (taxMatches.length > 0 && bankingMatches.length > 0) {
    phishingScore += 8;
  }

  if (
    matchedUrgency.length > 0 &&
    matchedPhishing.length > 0 &&
    suspiciousUrls.length > 0
  ) {
    phishingScore += 10;
  }

  phishingScore = Math.min(phishingScore, 97);

  // ==========================================
  // SPAM SCORE
  // ==========================================
  let spamScore = 0;

  spamScore += Math.min(35, matchedSpam.length * 5);

  if (matchedSpam.length > 5) {
    spamScore += 20;
  }

  if (matchedSpam.length > 0 && matchedUrgency.length > 0) {
    spamScore += Math.min(12, matchedUrgency.length * 2);
  }

  if (matchedSocialEng.length > 3) {
    spamScore += 15;
  }

  if (
    matchedLookalikeBrands.length > 0 &&
    matchedSpam.length > 0
  ) {
    spamScore += 10;
  }

  if (
    suspiciousUrls.length > 0 &&
    matchedSpam.length > 0
  ) {
    spamScore += 10;
  }

  spamScore = Math.min(spamScore, 95);

  // ==========================================
  // VERDICT
  // ==========================================
  let verdict = "legitimate";
  let riskScore = 3;
  let confidence = 95;

  const strongPhishingSignal =
    criticalPhishingMatches.length > 0 ||
    suspiciousUrls.length > 0 ||
    matchedCredentials.length > 0 ||
    matchedLookalikeBrands.length > 0 ||
    bankingMatches.length > 0 ||
    taxMatches.length > 0 ||
    cryptoMatches.length > 0;

  if (phishingScore >= 60 && strongPhishingSignal) {
    verdict = "phishing";
    riskScore = Math.min(99, phishingScore);

    confidence = Math.min(
      99,
      72 +
      Math.min(12, criticalPhishingMatches.length * 3) +
      Math.min(8, highPhishingMatches.length * 2) +
      Math.min(6, cryptoMatches.length * 2) +
      Math.min(6, taxMatches.length * 2) +
      Math.min(6, bankingMatches.length * 2) +
      Math.min(9, suspiciousUrls.length * 3) +
      Math.min(6, matchedLookalikeBrands.length * 2) +
      Math.min(5, matchedCredentials.length)
    );
  } else if (spamScore >= 40) {
    verdict = "spam";
    riskScore = Math.min(95, Math.round(20 + spamScore * 0.8));

    confidence = Math.min(
      97,
      Math.max(
        75,
        Math.round(78 + matchedSpam.length * 2 + matchedSocialEng.length)
      )
    );
  } else {
    // Keep legitimate emails conservative.
    const keywordRisk = Math.min(
      20,
      criticalPhishingMatches.length * 7 +
      highPhishingMatches.length * 5 +
      mediumPhishingMatches.length * 3
    );

    const categoryRisk = Math.min(
      12,
      cryptoMatches.length * 4 +
      taxMatches.length * 4 +
      bankingMatches.length * 4
    );

    const credentialRisk = Math.min(
      12,
      matchedCredentials.length * 3
    );

    const urgencyRisk = Math.min(
      8,
      matchedUrgency.length * 2
    );

    const spamRisk = Math.min(
      10,
      matchedSpam.length * 2
    );

    const urlRisk = Math.min(
      15,
      suspiciousUrls.length * 8
    );

    const senderRisk = senderLooksOff ? 10 : 0;

    const brandRisk = Math.min(
      10,
      matchedLookalikeBrands.length * 5
    );

    const combinedRisk =
      keywordRisk +
      categoryRisk +
      credentialRisk +
      urgencyRisk +
      spamRisk +
      urlRisk +
      senderRisk +
      brandRisk;

    riskScore = Math.min(
      49,
      Math.max(3, Math.round(combinedRisk / 3))
    );

    confidence = Math.min(
      98,
      Math.max(70, 98 - Math.round(riskScore * 0.7))
    );
  }

  // ==========================================
  // REASONS
  // ==========================================
  const reasons = [];

  if (criticalPhishingMatches.length > 0) {
    reasons.push(
      `CRITICAL phishing keywords detected: ${criticalPhishingMatches
        .slice(0, 3)
        .join(", ")}${criticalPhishingMatches.length > 3 ? "..." : ""}`
    );
  }

  if (cryptoMatches.length > 0) {
    reasons.push(
      `Cryptocurrency scam indicators: ${cryptoMatches
        .slice(0, 2)
        .join(", ")}`
    );
  }

  if (taxMatches.length > 0) {
    reasons.push(
      `Tax/IRS impersonation indicators: ${taxMatches
        .slice(0, 2)
        .join(", ")}`
    );
  }

  if (bankingMatches.length > 0) {
    reasons.push(
      `Banking impersonation indicators: ${bankingMatches
        .slice(0, 2)
        .join(", ")}`
    );
  }

  if (highPhishingMatches.length > 0) {
    reasons.push(
      `High-risk phishing keywords: ${highPhishingMatches
        .slice(0, 2)
        .join(", ")}`
    );
  }

  if (mediumPhishingMatches.length > 0) {
    reasons.push(
      `Phishing-related keywords detected: ${mediumPhishingMatches
        .slice(0, 2)
        .join(", ")}`
    );
  }

  if (matchedSpam.length > 0) {
    reasons.push(
      `Spam-related keywords detected: ${matchedSpam
        .slice(0, 3)
        .join(", ")}`
    );
  }

  if (matchedUrgency.length > 0 && matchedPhishing.length > 0) {
    reasons.push(
      `Urgency + phishing combination: ${matchedUrgency
        .slice(0, 2)
        .join(", ")}`
    );
  }

  if (matchedCredentials.length > 0) {
    reasons.push(
      `Credential harvesting indicators: ${matchedCredentials
        .slice(0, 2)
        .join(", ")}`
    );
  }

  if (suspiciousUrls.length > 0) {
    reasons.push(
      `🔗 ${suspiciousUrls.length} suspicious URL(s) detected`
    );
  }

  if (senderLooksOff) {
    reasons.push(
      "⚠️ Sender format appears unusual or potentially spoofed"
    );
  }

  if (matchedLookalikeBrands.length > 0) {
    reasons.push(
      `Brand impersonation indicators: ${matchedLookalikeBrands
        .slice(0, 4)
        .join(", ")}${matchedLookalikeBrands.length > 4 ? "..." : ""}`
    );
  }

  if (matchedSocialEng.length > 2) {
    reasons.push(
      "Social engineering tactics detected: urgency, pressure, or scarcity"
    );
  }

  if (urlMatches.length === 0 && verdict !== "phishing") {
    reasons.push("No URLs detected in the email body");
  }

  if (verdict === "legitimate") {
    if (matchedPhishing.length === 0 && matchedSpam.length === 0) {
      reasons.push(
        "✓ No significant phishing or spam indicators detected"
      );
    } else {
      reasons.push(
        "✓ Detected indicators remained below the threat threshold"
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
    spamScore,

    criticalMatches: criticalPhishingMatches.length,
    highMatches: highPhishingMatches.length,
    mediumMatches: mediumPhishingMatches.length,
    cryptoMatches: cryptoMatches.length,
    taxMatches: taxMatches.length,
    bankingMatches: bankingMatches.length,

    urgencyMatches: matchedUrgency.length,
    credentialMatches: matchedCredentials.length,
    socialEngineeringMatches: matchedSocialEng.length
  };
}


/* =========================================================
   HELPERS
   ========================================================= */

function findMatches(text, keywords) {
  if (!text || !Array.isArray(keywords)) {
    return [];
  }

  const normalizedText = text.toLowerCase();
  const matches = [];
  const seen = new Set();

  // Longest phrases first.
  // This reduces duplicate/overlapping matches in scoring.
  const sortedKeywords = [...new Set(
    keywords
      .filter(Boolean)
      .map(keyword => keyword.toLowerCase().trim())
      .filter(Boolean)
  )].sort((a, b) => b.length - a.length);

  for (const keyword of sortedKeywords) {
    if (seen.has(keyword)) continue;

    if (normalizedText.includes(keyword)) {
      matches.push(keyword);
      seen.add(keyword);
    }
  }

  return matches;
}


function isSuspiciousUrl(url) {
  try {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname.toLowerCase();

    const hasIpAddress =
      /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);

    const hasPunycode =
      hostname.includes("xn--");

    const suspiciousTerms = [
      "verify-",
      "-verify",
      "verification-",
      "-verification",
      "secure-",
      "-secure",
      "security-",
      "-security",
      "account-",
      "-account",
      "login-",
      "-login",
      "signin-",
      "-signin",
      "sign-in-",
      "-sign-in",
      "update-",
      "-update",
      "confirm-",
      "-confirm",
      "auth-",
      "-auth",
      "bank-verify",
      "payment-",
      "-payment",
      "billing-",
      "-billing",
      "credential-",
      "-credential",
      "password-",
      "-password",
      "wallet-",
      "-wallet"
    ];

    const hasSuspiciousTerm = suspiciousTerms.some(
      term => hostname.includes(term)
    );

    // Only flag mixed alphanumeric hostnames as a weak
    // structural signal; digits alone are common in real domains.
    const hasMixedAlphaNumeric =
      /[a-z]/.test(hostname) &&
      /\d/.test(hostname);

    const hasSuspiciousStructure =
      hostname.includes("--") ||
      hostname.split(".").length >= 5;

    return (
      hasIpAddress ||
      hasPunycode ||
      hasSuspiciousTerm ||
      hasMixedAlphaNumeric ||
      hasSuspiciousStructure
    );
  } catch (error) {
    return true;
  }
}


function getSenderDomain(sender) {
  if (!sender || !sender.includes("@")) {
    return "Unknown";
  }

  return sender
    .split("@")
    .pop()
    .toLowerCase()
    .trim();
}


function isUnusualSender(sender) {
  if (!sender || !isValidEmail(sender)) {
    return false;
  }

  const parts = sender.split("@");

  if (parts.length !== 2) {
    return true;
  }

  const localPart = parts[0] || "";
  const domain = parts[1] || "";

  const hasManyNumbers =
    (localPart.match(/\d/g) || []).length >= 5;

  const hasRepeatedHyphens =
    domain.includes("--");

  const hasRepeatedDots =
    domain.includes("..");

  const hasSuspiciousDomainPattern =
    domain.startsWith("-") ||
    domain.endsWith("-") ||
    domain.includes("secure-login") ||
    domain.includes("account-verify") ||
    domain.includes("verify-account");

  const spoofedPatterns = [
    "paypa",
    "amaz0n",
    "amaz0",
    "appl",
    "microsof",
    "googl",
    "facebok",
    "whatsap",
    "linkedln",
    "bankofamerica",
    "wellsfarg",
    "chasebank"
  ];

  const hasSpoofedPattern = spoofedPatterns.some(
    pattern => domain.includes(pattern)
  );

  return (
    hasManyNumbers ||
    hasRepeatedHyphens ||
    hasRepeatedDots ||
    hasSuspiciousDomainPattern ||
    hasSpoofedPattern
  );
}


function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}


function renderResults(result) {

 if (resultEmpty) resultEmpty.style.display = "none";

 if (resultContent) resultContent.style.display = "block";



 if (verdictRow) {

  verdictRow.className = `verdict-row verdict-${result.verdict}`;
 }



 if (verdictValue) {

  const verdictText = result.verdict === "phishing" ? "🚨 PHISHING" :

           result.verdict === "spam" ? "⚠️ SPAM" :

           "✓ LEGITIMATE";

  verdictValue.textContent = verdictText;

 }



 if (riskScoreEl) {

  riskScoreEl.textContent = result.riskScore;

 }



 if (confidenceScoreEl) {

  confidenceScoreEl.textContent = result.confidence;

 }



 if (reasonList) {

  reasonList.innerHTML = result.reasons

   reasons.map(reason => `<li>${reason}</li>`).join("")

 }



 if (urlsDetectedEl) {

  urlsDetectedEl.textContent = result.urlMatches.length;

 }



 if (urlsSuspiciousEl) {

  urlsSuspiciousEl.textContent = result.suspiciousUrls.length;

 }



 if (keywordList) {

  const allKeywords = [

   ...result.matchedPhishing.slice(0, 5),

   ...result.matchedSpam.slice(0, 3),

   ...result.matchedCredentials.slice(0, 2)

  ].slice(0, 8);



  keywordList.innerHTML = allKeywords.length > 0
  ? allKeywords.map(kw => `<span class="keyword-tag">${kw}</span>`).join("")
  : "<p>No keywords matched</p>";
 }

}



function clearFieldErrors() {

 [senderInput, subjectInput, bodyInput].forEach(input => {

  if (input) {

   input.classList.remove("input-error");

   if (input.parentNode) {

    const errorEl = input.parentNode.querySelector(".error-message");

    if (errorEl) errorEl.remove();

   }

  }

 });

}



function setFieldError(input, message) {

 if (!input) return;

 input.classList.add("input-error");

 const errorEl = document.createElement("div");

 errorEl.className = "error-message";

 errorEl.textContent = message;

 input.parentNode.appendChild(errorEl);

}

function generateReport(result) {

 const { jsPDF } = window;

 if (!jsPDF) {

  alert("PDF library not loaded. Please refresh the page.");

  return;

 }



 const doc = new jsPDF();

 const pageHeight = doc.internal.pageSize.getHeight();

 const pageWidth = doc.internal.pageSize.getWidth();

 const margin = 15;

 let y = margin;



 const addText = (text, fontSize = 11, fontStyle = "normal", spacing = 4) => {

  doc.setFont("helvetica", fontStyle);

  doc.setFontSize(fontSize);

  const lines = doc.splitTextToSize(text, pageWidth - 2 * margin);

  doc.text(lines, margin, y);

  y += (lines.length * fontSize) / 3 + spacing;

 };



 const addSectionHeading = (heading) => {

  doc.setFont("helvetica", "bold");

  doc.setFontSize(13);

  doc.text(heading, margin, y);

  y += 8;

 };



 // Title

 doc.setFont("helvetica", "bold");

 doc.setFontSize(16);

 doc.text("ClueWell Mail - Security Report", margin, y);

 y += 12;



 // Summary

 addSectionHeading("Analysis Summary");

 addText(`Verdict: ${result.verdict.toUpperCase()}`);

 addText(`Risk Score: ${result.riskScore}/100`);

 addText(`Confidence: ${result.confidence}%`);

 y += 4;



 // Reasons

 addSectionHeading("Detection Reasons");

 result.reasons.forEach(reason => {

  addText(`• ${reason}`, 10);

 });

 y += 4;



 // Keywords

 addSectionHeading("Keywords Detected");

 addText(`Critical Phishing Keywords: ${result.criticalMatches || 0}`);

 addText(`High-Risk Keywords: ${result.highMatches || 0}`);

 addText(`Crypto Scam Indicators: ${result.cryptoMatches || 0}`);

 addText(`Tax/IRS Impersonation: ${result.taxMatches || 0}`);

 addText(`Banking Impersonation: ${result.bankingMatches || 0}`);

 y += 4;



 // URLs

 addSectionHeading("URL Analysis");

 addText(`URLs Detected: ${result.urlMatches.length}`);

 addText(`Suspicious URLs: ${result.suspiciousUrls.length}`);



 // Disclaimer

 addSectionHeading("Disclaimer");

 addText(

  "ClueWell Mail uses client-side keyword and rule-based analysis. The result is an indication only and should not be treated as a guaranteed security decision.",

  9

 );



 // Footer

 doc.setFont("helvetica", "normal");

 doc.setFontSize(8);

 doc.text(

  `Generated: ${new Date().toLocaleString()}`,

  pageWidth - margin,

  pageHeight - 10,

  { align: "right" }

 );



 doc.save("ClueWell-Mail-report-enhanced.pdf");

}
