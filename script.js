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

  // ============================================================
  // 1. ACCOUNT VERIFICATION
  // ============================================================

  "verify your account",
  "verify account",
  "account verification",
  "verify account now",
  "verify your identity",
  "identity verification",
  "verify identity",
  "confirm your identity",
  "confirm identity",
  "identity confirmation",
  "account confirmation",
  "confirm your account",
  "confirm account",
  "account validation",
  "validate your account",
  "validate account",
  "validate your identity",
  "identity validation",
  "security verification",
  "security validation",
  "security confirmation",
  "security check",
  "account security check",
  "account verification required",
  "account verification needed",
  "verification required",
  "verification needed",
  "verification request",
  "verification process",
  "complete verification",
  "complete account verification",
  "complete identity verification",
  "finish verification",
  "finish account verification",
  "verification pending",
  "pending verification",
  "mandatory verification",
  "required verification",
  "additional verification",
  "additional identity verification",
  "reverify your account",
  "re-verify your account",
  "reverify account",
  "re-verify account",
  "verify again",
  "confirm again",
  "reconfirm your account",
  "reconfirm account",
  "account confirmation required",
  "identity confirmation required",
  "security confirmation required",
  "verification action required",
  "account verification action",
  "verify to continue",
  "verify before continuing",
  "verify before access",
  "verify before login",
  "verification before access",
  "verification before login",

  // ============================================================
  // 2. LOGIN / SIGN-IN
  // ============================================================

  "login required",
  "login now",
  "login immediately",
  "login to continue",
  "log in to continue",
  "sign in to continue",
  "signin required",
  "sign-in required",
  "sign in now",
  "signin now",
  "sign-in now",
  "login verification",
  "login confirmation",
  "login authentication",
  "authentication required",
  "authenticate your account",
  "authenticate account",
  "authentication needed",
  "authentication request",
  "authentication failure",
  "login failure",
  "sign in again",
  "login again",
  "re-login",
  "relogin",
  "session login required",
  "session expired login",
  "login session expired",
  "your session expired",
  "session has expired",
  "secure login",
  "secure sign in",
  "secure signin",
  "account login",
  "account sign in",
  "account signin",
  "member login",
  "member sign in",
  "portal login",
  "portal sign in",
  "customer login",
  "customer sign in",
  "user login",
  "user sign in",
  "web login",
  "online login",
  "online sign in",
  "access your account",
  "access account",
  "restore account access",
  "regain account access",
  "restore login access",
  "unlock login",
  "unlock account access",

  // ============================================================
  // 3. PASSWORD
  // ============================================================

  "password required",
  "password verification",
  "verify your password",
  "confirm your password",
  "confirm password",
  "password confirmation",
  "password validation",
  "validate password",
  "password authentication",
  "password reset required",
  "reset your password",
  "reset password",
  "password reset",
  "password recovery",
  "recover your password",
  "recover password",
  "forgot password",
  "forgotten password",
  "password expired",
  "password has expired",
  "password expiration",
  "password expiry",
  "password update required",
  "update your password",
  "update password",
  "change your password",
  "change password",
  "create new password",
  "set new password",
  "new password required",
  "temporary password",
  "temporary login password",
  "password unlock",
  "unlock password",
  "password security",
  "password security check",
  "password confirmation required",
  "password authentication required",
  "password credentials",
  "account password",
  "login password",
  "user password",
  "current password",
  "old password",
  "new password",
  "password credentials required",
  "enter your password",
  "provide your password",
  "submit your password",
  "send your password",
  "share your password",

  // ============================================================
  // 4. USERNAME / USER ID / CREDENTIALS
  // ============================================================

  "username required",
  "username verification",
  "verify username",
  "confirm username",
  "username confirmation",
  "user id required",
  "user id verification",
  "verify user id",
  "confirm user id",
  "user identification",
  "user credentials",
  "login credentials",
  "account credentials",
  "credentials required",
  "credentials verification",
  "credential verification",
  "verify credentials",
  "confirm credentials",
  "credential confirmation",
  "authentication credentials",
  "account login credentials",
  "login information",
  "login details",
  "account login details",
  "account access credentials",
  "access credentials",
  "provide credentials",
  "submit credentials",
  "enter credentials",
  "send credentials",
  "share credentials",
  "update credentials",
  "confirm login details",
  "verify login details",
  "provide login details",
  "submit login details",
  "enter login details",
  "account information required",
  "account details required",
  "user information required",

  // ============================================================
  // 5. OTP / ONE-TIME PASSWORD
  // ============================================================

  "otp required",
  "otp verification",
  "verify otp",
  "confirm otp",
  "enter otp",
  "submit otp",
  "provide otp",
  "share otp",
  "send otp",
  "otp confirmation",
  "otp authentication",
  "one time password",
  "one-time password",
  "one time passcode",
  "one-time passcode",
  "verification code",
  "verification code required",
  "verification code request",
  "authentication code",
  "authentication code required",
  "security code",
  "security code required",
  "confirmation code",
  "confirmation code required",
  "login code",
  "login code required",
  "access code",
  "access code required",
  "temporary verification code",
  "temporary security code",
  "temporary authentication code",
  "enter verification code",
  "enter authentication code",
  "enter security code",
  "enter confirmation code",
  "submit verification code",
  "submit authentication code",
  "submit security code",
  "provide verification code",
  "provide authentication code",
  "provide security code",
  "send verification code",
  "send authentication code",
  "send security code",
  "share verification code",
  "share authentication code",
  "share security code",
  "otp expired",
  "otp has expired",
  "request new otp",
  "generate new otp",
  "new verification code",
  "new security code",
  "new authentication code",

  // ============================================================
  // 6. MFA / 2FA
  // ============================================================

  "two factor authentication",
  "two-factor authentication",
  "2fa verification",
  "2fa authentication",
  "2fa code",
  "2fa verification code",
  "two factor verification",
  "multi factor authentication",
  "multi-factor authentication",
  "mfa verification",
  "mfa authentication",
  "mfa code",
  "mfa verification code",
  "authentication app code",
  "authenticator code",
  "authenticator verification",
  "authentication token",
  "security token",
  "verification token",
  "access token",
  "temporary token",
  "token verification",
  "token authentication",
  "enter authentication token",
  "provide authentication token",
  "submit authentication token",
  "verify authentication token",
  "confirm authentication token",
  "mfa required",
  "mfa verification required",
  "2fa required",
  "2fa verification required",
  "additional authentication required",
  "additional security verification",

  // ============================================================
  // 7. PIN / SECURITY PIN
  // ============================================================

  "pin required",
  "pin verification",
  "verify pin",
  "confirm pin",
  "enter pin",
  "submit pin",
  "provide pin",
  "share pin",
  "send pin",
  "security pin",
  "security pin verification",
  "account pin",
  "account pin verification",
  "payment pin",
  "payment pin verification",
  "transaction pin",
  "transaction pin verification",
  "banking pin",
  "bank pin",
  "atm pin",
  "card pin",
  "pin confirmation",
  "pin authentication",
  "pin reset",
  "reset pin",
  "update pin",
  "change pin",
  "new pin required",

  // ============================================================
  // 8. CREDIT / DEBIT CARD
  // ============================================================

  "card verification",
  "verify your card",
  "verify card",
  "card confirmation",
  "confirm your card",
  "confirm card",
  "card authentication",
  "card security verification",
  "card security check",
  "card details required",
  "card information required",
  "payment card verification",
  "payment card details",
  "credit card details",
  "debit card details",
  "credit card verification",
  "debit card verification",
  "credit card information",
  "debit card information",
  "card number",
  "card number required",
  "enter card number",
  "provide card number",
  "submit card number",
  "share card number",
  "card expiry",
  "card expiration",
  "expiration date",
  "expiry date",
  "expiry verification",
  "cvv",
  "cvv verification",
  "cvv required",
  "enter cvv",
  "provide cvv",
  "submit cvv",
  "share cvv",
  "cvc",
  "cvc verification",
  "cvc required",
  "enter cvc",
  "card security code",
  "card security number",
  "billing information",
  "billing details",
  "billing verification",
  "billing address verification",
  "payment information",
  "payment details",
  "payment verification",
  "payment confirmation",

  // ============================================================
  // 9. BANKING
  // ============================================================

  "bank account verification",
  "verify bank account",
  "bank account confirmation",
  "confirm bank account",
  "banking verification",
  "online banking verification",
  "online banking authentication",
  "mobile banking verification",
  "bank login",
  "bank login required",
  "bank credentials",
  "banking credentials",
  "bank account details",
  "bank account information",
  "bank details required",
  "bank information required",
  "account number required",
  "enter account number",
  "provide account number",
  "submit account number",
  "share account number",
  "routing number",
  "routing number required",
  "ifsc code",
  "ifsc verification",
  "ifsc required",
  "swift code",
  "swift verification",
  "iban",
  "iban verification",
  "bank transfer verification",
  "wire transfer verification",
  "transaction verification",
  "transaction authentication",
  "payment authentication",
  "bank security verification",
  "bank security check",
  "bank account security",
  "bank account update",
  "update bank details",
  "update banking information",
  "confirm banking information",
  "verify banking information",
  "bank profile verification",
  "bank profile update",

  // ============================================================
  // 10. PAYMENT / TRANSACTION
  // ============================================================

  "payment verification required",
  "payment verification",
  "verify payment",
  "confirm payment",
  "payment confirmation required",
  "payment authentication required",
  "transaction verification required",
  "verify transaction",
  "confirm transaction",
  "transaction confirmation",
  "transaction authentication required",
  "payment failed",
  "payment failure",
  "payment rejected",
  "payment declined",
  "payment reversed",
  "payment issue",
  "payment problem",
  "payment account verification",
  "payment method verification",
  "verify payment method",
  "confirm payment method",
  "update payment method",
  "payment method expired",
  "payment details required",
  "payment information required",
  "billing verification required",
  "billing information verification",
  "billing account verification",
  "transaction pending verification",
  "transaction security verification",
  "secure transaction verification",

  // ============================================================
  // 11. ACCOUNT SUSPENSION / LOCK
  // ============================================================

  "account suspended",
  "account suspension",
  "account will be suspended",
  "account has been suspended",
  "account is suspended",
  "suspend your account",
  "suspension notice",
  "suspension warning",
  "suspension alert",
  "account locked",
  "account lock",
  "account has been locked",
  "account is locked",
  "account will be locked",
  "lock your account",
  "temporary account lock",
  "permanent account lock",
  "security lock",
  "security lockdown",
  "account restriction",
  "account restricted",
  "account access restricted",
  "account access blocked",
  "account blocked",
  "access blocked",
  "login blocked",
  "login restricted",
  "account disabled",
  "account deactivated",
  "account terminated",
  "account closure",
  "account closing",
  "account cancellation",
  "account at risk",
  "account security risk",
  "account compromised",
  "account may be compromised",
  "account security issue",
  "security issue detected",
  "security problem detected",

  // ============================================================
  // 12. UNUSUAL / SUSPICIOUS ACTIVITY
  // ============================================================

  "unusual activity",
  "unusual account activity",
  "unusual login",
  "unusual sign in",
  "unusual signin",
  "unrecognized login",
  "unrecognized sign in",
  "unrecognized signin",
  "unknown login",
  "unknown sign in",
  "unknown device",
  "unknown device detected",
  "new device detected",
  "new login detected",
  "new sign in detected",
  "new signin detected",
  "suspicious activity",
  "suspicious account activity",
  "suspicious login",
  "suspicious sign in",
  "suspicious transaction",
  "suspicious payment",
  "suspicious access",
  "suspicious device",
  "suspicious location",
  "unusual transaction",
  "unusual payment",
  "unusual purchase",
  "unusual access",
  "unusual location",
  "unusual device",
  "unusual request",
  "unrecognized transaction",
  "unrecognized payment",
  "unrecognized purchase",
  "unrecognized activity",
  "unauthorized activity",
  "unauthorized access",
  "unauthorized login",
  "unauthorized transaction",
  "unauthorized payment",
  "unauthorized purchase",
  "security event detected",
  "security incident detected",
  "security alert",
  "security warning",
  "security notification",

  // ============================================================
  // 13. ACCOUNT UPDATE
  // ============================================================

  "account update required",
  "update your account",
  "update account",
  "account information update",
  "account details update",
  "update account information",
  "update account details",
  "confirm account update",
  "verify account update",
  "security update required",
  "mandatory account update",
  "required account update",
  "account profile update",
  "profile verification",
  "verify your profile",
  "confirm your profile",
  "profile confirmation",
  "profile update required",
  "customer information update",
  "customer details update",
  "user information update",
  "personal information update",
  "personal details update",
  "contact information update",
  "update contact information",
  "update phone number",
  "update mobile number",
  "update email address",
  "confirm email address",
  "verify email address",
  "email verification required",
  "email address verification",
  "phone verification required",
  "phone number verification",

  // ============================================================
  // 14. EMAIL ACCOUNT
  // ============================================================

  "email account verification",
  "verify email account",
  "email verification",
  "email confirmation",
  "confirm email",
  "confirm email address",
  "email account security",
  "email account suspended",
  "email account locked",
  "mailbox verification",
  "mailbox security verification",
  "mailbox suspended",
  "mailbox disabled",
  "mailbox full",
  "email storage exceeded",
  "storage limit exceeded",
  "email storage limit",
  "email security alert",
  "email security warning",
  "email login required",
  "email password reset",
  "email password verification",
  "email credentials",
  "mail credentials",
  "mailbox credentials",
  "webmail verification",
  "webmail login",
  "webmail security",
  "mail account update",
  "email account update",

  // ============================================================
  // 15. RECOVERY
  // ============================================================

  "account recovery",
  "recover your account",
  "recover account",
  "account recovery required",
  "account recovery verification",
  "recovery verification",
  "recovery code",
  "recovery code required",
  "recovery code verification",
  "backup code",
  "backup code required",
  "backup verification code",
  "recovery key",
  "recovery key required",
  "security recovery",
  "security recovery process",
  "restore account",
  "restore access",
  "restore account access",
  "restore security access",
  "recover account access",
  "recover login access",
  "account restoration",
  "access restoration",
  "recovery request",
  "account recovery request",
  "verify recovery request",
  "confirm recovery request",
  "recovery authentication",
  "recovery authentication required",

  // ============================================================
  // 16. IDENTITY / PERSONAL INFORMATION
  // ============================================================

  "personal information verification",
  "personal information required",
  "personal details verification",
  "personal details required",
  "identity information",
  "identity details",
  "identity documents",
  "identity document verification",
  "id verification",
  "id verification required",
  "government id verification",
  "government identification",
  "identification verification",
  "identity check",
  "identity check required",
  "customer identity verification",
  "customer verification",
  "customer identification",
  "user identity verification",
  "user identity confirmation",
  "date of birth verification",
  "date of birth confirmation",
  "address verification",
  "home address verification",
  "phone number verification",
  "mobile number verification",
  "social security verification",
  "tax identification verification",
  "tax id verification",
  "passport verification",
  "license verification",
  "identity validation required",
  "submit identification",
  "provide identification",
  "upload identification",
  "upload identity document",
  "submit identity document",
  "provide identity document",

  // ============================================================
  // 17. DELIVERY / SHIPPING PHISHING
  // ============================================================

  "delivery verification",
  "delivery address verification",
  "verify delivery address",
  "confirm delivery address",
  "shipping address verification",
  "shipment verification",
  "package verification",
  "parcel verification",
  "delivery issue",
  "delivery problem",
  "delivery failed",
  "delivery attempt failed",
  "package delivery failed",
  "parcel delivery failed",
  "shipment delayed",
  "delivery delayed",
  "package delayed",
  "parcel delayed",
  "address issue",
  "incorrect delivery address",
  "invalid delivery address",
  "confirm shipping details",
  "update shipping address",
  "update delivery address",
  "redelivery required",
  "redelivery confirmation",
  "delivery payment required",
  "shipping payment required",
  "customs payment required",
  "customs verification",
  "package held",
  "parcel held",
  "shipment held",
  "package on hold",
  "delivery on hold",

  // ============================================================
  // 18. TAX / GOVERNMENT / AUTHORITY
  // ============================================================

  "tax verification",
  "tax account verification",
  "tax account update",
  "tax refund verification",
  "tax refund confirmation",
  "tax payment verification",
  "tax information required",
  "tax details required",
  "government verification",
  "government account verification",
  "official verification",
  "official account verification",
  "official notice",
  "official security alert",
  "compliance verification",
  "compliance required",
  "regulatory verification",
  "regulatory requirement",
  "legal verification",
  "legal notice",
  "mandatory compliance",
  "compliance action required",
  "submit tax information",
  "provide tax information",
  "confirm tax information",
  "verify taxpayer information",
  "identity verification required",
  "government id required",

  // ============================================================
  // 19. WORKPLACE / CORPORATE IMPERSONATION
  // ============================================================

  "ceo request",
  "executive request",
  "director request",
  "manager request",
  "boss request",
  "urgent request from manager",
  "urgent request from director",
  "urgent request from executive",
  "executive verification",
  "executive approval required",
  "management request",
  "finance department request",
  "accounting department request",
  "payroll verification",
  "employee verification",
  "employee account verification",
  "employee portal verification",
  "employee login",
  "employee credentials",
  "corporate account verification",
  "company account verification",
  "business account verification",
  "corporate security alert",
  "corporate security verification",
  "company security alert",
  "internal security alert",
  "internal account verification",
  "internal login required",
  "company password reset",
  "corporate password reset",
  "employee password reset",
  "hr verification",
  "human resources verification",
  "work account verification",
  "work email verification",
  "office account verification",

  // ============================================================
  // 20. FINANCIAL FRAUD / TRANSFER
  // ============================================================

  "urgent payment request",
  "urgent payment",
  "urgent transfer",
  "immediate payment",
  "immediate transfer",
  "wire transfer required",
  "wire transfer verification",
  "bank transfer required",
  "bank transfer verification",
  "fund transfer verification",
  "transfer authorization",
  "payment authorization",
  "payment approval required",
  "transfer approval required",
  "transaction approval required",
  "confirm transfer",
  "verify transfer",
  "authorize payment",
  "authorize transfer",
  "approve payment",
  "approve transfer",
  "send payment",
  "send funds",
  "transfer funds",
  "transfer money",
  "payment requested",
  "funds requested",
  "financial verification",
  "financial account verification",
  "financial information required",
  "financial details required",
  "beneficiary verification",
  "beneficiary confirmation",
  "recipient verification",
  "recipient confirmation",
  "bank beneficiary update",
  "payment beneficiary update",

  // ============================================================
  // 21. MONEY REQUEST + IMPERSONATION
  // ============================================================

  "need money urgently",
  "need money immediately",
  "send money urgently",
  "send money immediately",
  "send funds urgently",
  "send funds immediately",
  "transfer money urgently",
  "transfer funds urgently",
  "please send money",
  "please transfer money",
  "please send funds",
  "urgent money request",
  "urgent financial request",
  "emergency money request",
  "emergency payment request",
  "emergency transfer request",
  "keep this confidential",
  "keep this private",
  "do not tell anyone",
  "don't tell anyone",
  "do not contact me",
  "don't contact me",
  "do not call",
  "don't call",
  "cannot talk right now",
  "can't talk right now",
  "new phone number",
  "new number",
  "use this number",
  "contact me on this number",
  "send it to this account",
  "send it to this bank account",
  "send it immediately",
  "transfer it immediately",
  "need your help with a payment",
  "help me make a payment",
  "make a payment for me",

  // ============================================================
  // 22. FEAR / THREAT
  // ============================================================

  "immediate action required",
  "action required",
  "action is required",
  "urgent action required",
  "critical action required",
  "important action required",
  "failure to act",
  "failure to respond",
  "failure to comply",
  "failure to verify",
  "failure to confirm",
  "failure to update",
  "account will be closed",
  "account will be terminated",
  "account will be disabled",
  "account will be deleted",
  "account will be restricted",
  "access will be removed",
  "access will be revoked",
  "service will be suspended",
  "service will be terminated",
  "payment will be declined",
  "transaction will be cancelled",
  "transaction will be rejected",
  "security access will be removed",
  "you may lose access",
  "you will lose access",
  "risk losing access",
  "risk of account closure",
  "risk of suspension",
  "security threat detected",
  "security breach detected",
  "potential security breach",
  "security incident",
  "security compromise",
  "account compromise detected",
  "unauthorized access detected",
  "unauthorized activity detected",
  "immediate verification required",
  "immediate confirmation required",
  "immediate security action",

  // ============================================================
  // 23. DEADLINE / TIME PRESSURE
  // ============================================================

  "verify within 24 hours",
  "verify within 48 hours",
  "verify within 12 hours",
  "verify within 6 hours",
  "verify within 1 hour",
  "confirm within 24 hours",
  "confirm within 48 hours",
  "respond within 24 hours",
  "respond within 48 hours",
  "act within 24 hours",
  "act within 48 hours",
  "complete within 24 hours",
  "complete within 48 hours",
  "before midnight",
  "before tonight",
  "before end of day",
  "by end of day",
  "deadline today",
  "deadline tomorrow",
  "final deadline",
  "verification deadline",
  "security deadline",
  "account deadline",
  "last day to verify",
  "last day to confirm",
  "last chance to verify",
  "last chance to confirm",
  "verification expires",
  "verification link expires",
  "link expires",
  "access expires",
  "session expires",
  "offer expires",
  "request expires",
  "action expires",
  "act immediately",
  "act now",
  "respond immediately",
  "respond now",
  "verify immediately",
  "confirm immediately",
  "update immediately",
  "login immediately",
  "click immediately",
  "do this now",
  "complete this now",

  // ============================================================
  // 24. CLICK / LINK ACTION
  // ============================================================

  "click here",
  "click below",
  "click the link",
  "click this link",
  "click to verify",
  "click to confirm",
  "click to authenticate",
  "click to secure",
  "click to continue",
  "click to restore",
  "click to unlock",
  "click to update",
  "click to login",
  "click to sign in",
  "click to access",
  "click to review",
  "click to validate",
  "click to activate",
  "click to complete",
  "follow the link",
  "follow this link",
  "use the link",
  "use this secure link",
  "open the link",
  "open this link",
  "visit the link",
  "access the link",
  "secure link",
  "verification link",
  "authentication link",
  "login link",
  "account verification link",
  "password reset link",
  "account recovery link",
  "security link",
  "update link",
  "confirmation link",
  "activation link",
  "access link",

  // ============================================================
  // 25. AUTHORITY / TRUST LANGUAGE
  // ============================================================

  "security team",
  "security department",
  "security center",
  "security office",
  "security administrator",
  "account administrator",
  "system administrator",
  "administrator notification",
  "support team",
  "customer support",
  "technical support",
  "account support",
  "security support",
  "fraud department",
  "fraud prevention",
  "fraud detection team",
  "fraud prevention team",
  "verification department",
  "identity verification department",
  "compliance department",
  "compliance team",
  "bank security team",
  "payment security team",
  "account protection team",
  "account protection department",
  "official security team",
  "official support team",
  "authorized representative",
  "authorized department",
  "security authority",
  "account authority",
  "official notification",
  "security notification",
  "security notice",
  "mandatory notice",
  "official warning",

  // ============================================================
  // 26. CUSTOMER / SERVICE ACCOUNT
  // ============================================================

  "customer account",
  "customer account verification",
  "customer verification required",
  "customer security verification",
  "customer security alert",
  "customer account suspended",
  "customer account locked",
  "customer account restricted",
  "member account verification",
  "member account security",
  "member account suspended",
  "subscriber verification",
  "subscriber account verification",
  "subscription verification",
  "service account verification",
  "service account security",
  "service account suspended",
  "user account verification",
  "user account security",
  "user account suspended",
  "user account locked",
  "client account verification",
  "client verification",
  "client account security",

  // ============================================================
  // 27. DOCUMENT / FILE / FORM
  // ============================================================

  "verify attached document",
  "confirm attached document",
  "document verification",
  "document authentication",
  "document confirmation",
  "document required",
  "identity document required",
  "security document",
  "secure document",
  "secure form",
  "verification form",
  "authentication form",
  "account verification form",
  "login form",
  "security form",
  "complete the form",
  "complete verification form",
  "submit the form",
  "submit verification form",
  "provide the information",
  "complete your information",
  "update your information",
  "confirm your information",
  "verify your information",
  "upload document",
  "upload identity",
  "upload identification",
  "upload verification document",

  // ============================================================
  // 28. RECENT ACTIVITY / DEVICE
  // ============================================================

  "new device",
  "new device login",
  "new device sign in",
  "new browser login",
  "new browser sign in",
  "new location login",
  "new location sign in",
  "new ip address",
  "new ip detected",
  "unknown ip address",
  "unknown location",
  "unrecognized device",
  "unrecognized browser",
  "unrecognized location",
  "unrecognized ip",
  "login from new device",
  "login from unknown device",
  "login from unknown location",
  "sign in from new device",
  "sign in from unknown device",
  "access from unknown location",
  "access from new device",
  "security activity detected",
  "recent security activity",
  "recent login activity",
  "recent sign in activity",
  "recent account activity",
  "review recent activity",
  "review login activity",
  "review account activity",

  // ============================================================
  // 29. SESSION / ACCESS
  // ============================================================

  "session expired",
  "session has expired",
  "session timeout",
  "session timed out",
  "access expired",
  "access has expired",
  "access verification",
  "access confirmation",
  "access authentication",
  "access authorization",
  "authorization required",
  "authorization verification",
  "authorize your account",
  "authorize account",
  "reauthorize account",
  "reauthorization required",
  "permission verification",
  "permission required",
  "account permission",
  "access permission",
  "security permission",
  "restore permission",
  "renew access",
  "renew account access",
  "renew authorization",
  "renew security access",

  // ============================================================
  // 30. RECOVERY / SECRET INFORMATION
  // ============================================================

  "security questions",
  "security question verification",
  "answer security questions",
  "confirm security questions",
  "recovery questions",
  "recovery question verification",
  "backup key",
  "backup key verification",
  "secret key",
  "private key",
  "security key",
  "security key verification",
  "recovery key verification",
  "authentication key",
  "authentication key verification",
  "access key",
  "access key verification",
  "account recovery key",
  "account recovery code",
  "backup recovery code",
  "emergency recovery code",
  "emergency access code",

  // ============================================================
  // 31. BENEFITS / REFUND / PAYMENT PHISHING
  // ============================================================

  "refund verification",
  "refund confirmation",
  "verify refund",
  "confirm refund",
  "refund account verification",
  "refund payment verification",
  "refund information required",
  "refund details required",
  "payment refund verification",
  "cashback verification",
  "cashback confirmation",
  "reward verification",
  "reward account verification",
  "bonus verification",
  "bonus account verification",
  "payout verification",
  "payout confirmation",
  "payout account verification",
  "payment recipient verification",
  "beneficiary verification required",

  // ============================================================
  // 32. COMMON PHISHING ACTION PHRASES
  // ============================================================

  "verify now",
  "confirm now",
  "authenticate now",
  "validate now",
  "update now",
  "secure now",
  "unlock now",
  "restore now",
  "recover now",
  "activate now",
  "renew now",
  "authorize now",
  "review now",
  "resolve now",
  "fix now",
  "complete now",
  "submit now",
  "respond now",
  "login now",
  "sign in now",
  "click now",
  "verify immediately",
  "confirm immediately",
  "authenticate immediately",
  "update immediately",
  "secure immediately",
  "restore immediately",
  "recover immediately",
  "authorize immediately",
  "review immediately",
  "resolve immediately",

  // ============================================================
  // 33. ACCOUNT PROTECTION
  // ============================================================

  "protect your account",
  "protect account",
  "secure your account",
  "secure account",
  "account protection",
  "account protection required",
  "security protection",
  "security protection required",
  "protect account access",
  "secure account access",
  "protect your identity",
  "protect identity",
  "identity protection",
  "identity security",
  "prevent account closure",
  "prevent account suspension",
  "prevent account lock",
  "prevent unauthorized access",
  "prevent unauthorized activity",
  "secure your login",
  "secure login access",
  "secure your credentials",
  "credential security",
  "password security required",

  // ============================================================
  // 34. CONFIRMATION / REVIEW
  // ============================================================

  "review your account",
  "review account",
  "review security settings",
  "review account information",
  "review account details",
  "review recent activity",
  "review recent login",
  "review transaction",
  "review payment",
  "review security alert",
  "confirm recent activity",
  "confirm recent login",
  "confirm recent transaction",
  "confirm recent payment",
  "confirm account activity",
  "confirm account ownership",
  "verify account ownership",
  "account ownership verification",
  "ownership confirmation",
  "security review required",
  "account review required",
  "payment review required",
  "transaction review required",

  // ============================================================
  // 35. ACCESS / OWNERSHIP
  // ============================================================

  "prove account ownership",
  "confirm account ownership",
  "verify account ownership",
  "ownership verification",
  "ownership confirmation",
  "prove your identity",
  "prove identity",
  "identity proof required",
  "proof of identity",
  "account access verification",
  "access ownership verification",
  "verify access",
  "confirm access",
  "validate access",
  "access verification required",
  "account access required",
  "secure access required",

  // ============================================================
  // 36. COMBINATION-STYLE PHRASES
  // ============================================================

  "verify your account immediately",
  "confirm your account immediately",
  "verify your identity immediately",
  "confirm your identity immediately",
  "verify your password immediately",
  "reset your password immediately",
  "confirm your payment immediately",
  "verify your payment immediately",
  "verify your card immediately",
  "confirm your card immediately",
  "verify your bank account immediately",
  "confirm your bank account immediately",
  "verify your banking information",
  "confirm your banking information",
  "verify your payment information",
  "confirm your payment information",
  "verify your login information",
  "confirm your login information",
  "verify your credentials immediately",
  "confirm your credentials immediately",
  "update your account immediately",
  "secure your account immediately",
  "restore your account immediately",
  "unlock your account immediately",
  "complete verification immediately",
  "complete security verification immediately",
  "complete identity verification immediately",
  "complete payment verification immediately",
  "complete account verification immediately",

  // ============================================================
  // 37. FINAL / HIGH-PRESSURE LANGUAGE
  // ============================================================

  "final warning",
  "final notice",
  "final security notice",
  "final verification notice",
  "final account notice",
  "last warning",
  "last notice",
  "last security warning",
  "last verification request",
  "urgent security notice",
  "urgent account notice",
  "urgent verification notice",
  "critical security alert",
  "critical account alert",
  "critical verification request",
  "immediate attention required",
  "your immediate attention is required",
  "your action is required",
  "your response is required",
  "your verification is required",
  "your confirmation is required",
  "your authentication is required",
  "your account requires attention",
  "your account requires verification",
  "your account requires confirmation",
  "your account requires authentication",

  // ============================================================
  // 38. PHISHING-STYLE LINK CONTEXT
  // ============================================================

  "secure verification portal",
  "account verification portal",
  "security verification portal",
  "login verification portal",
  "account security portal",
  "secure account portal",
  "secure login portal",
  "authentication portal",
  "verification portal",
  "verification webpage",
  "secure verification page",
  "account verification page",
  "login verification page",
  "security verification page",
  "password reset page",
  "account recovery page",
  "secure account page",
  "authentication page",
  "secure login page",
  "account access page",

  // ============================================================
  // 39. COMMON IMPERSONATION LANGUAGE
  // ============================================================

  "we detected",
  "we noticed",
  "we have detected",
  "our system detected",
  "our system has detected",
  "our security system detected",
  "security system detected",
  "automated security alert",
  "automated verification",
  "system verification required",
  "system security check",
  "system administrator",
  "account administrator",
  "security administrator",
  "official account",
  "official security notification",
  "official account notice",
  "authorized security notification",
  "authorized verification request",
  "mandatory security check",

  // ============================================================
  // 40. GENERAL HIGH-RISK TERMS
  // ============================================================

  "credential",
  "credentials",
  "authentication",
  "authenticate",
  "authorization",
  "authorize",
  "verification",
  "verify",
  "confirmation",
  "confirm",
  "validation",
  "validate",
  "security check",
  "security verification",
  "account security",
  "account access",
  "login",
  "signin",
  "sign in",
  "password",
  "passcode",
  "pass code",
  "otp",
  "pin",
  "cvv",
  "cvc",
  "security code",
  "verification code",
  "authentication code",
  "access code",
  "recovery code",
  "backup code",
  "security token",
  "authentication token",
  "account number",
  "bank account",
  "banking information",
  "payment information",
  "card information",
  "personal information",
  "identity information",
  "identity verification",
  "financial information"
];

const spamKeywords = [
  // =========================
  // GENERAL PROMOTIONAL
  // =========================
  "special offer",
  "special promotion",
  "exclusive offer",
  "exclusive deal",
  "limited offer",
  "limited deal",
  "great offer",
  "amazing offer",
  "fantastic offer",
  "unmissable offer",
  "incredible offer",
  "best offer",
  "hot offer",
  "top deal",
  "deal of the day",
  "deal alert",
  "daily deal",
  "weekly deal",
  "monthly deal",
  "flash deal",
  "flash sale",
  "special deal",
  "promotional offer",
  "promotional deal",
  "promotional email",
  "marketing offer",
  "customer offer",
  "exclusive promotion",
  "member offer",
  "members only",
  "vip offer",
  "vip deal",

  // =========================
  // DISCOUNTS / COUPONS
  // =========================
  "discount",
  "discount offer",
  "discount code",
  "discount coupon",
  "discount voucher",
  "special discount",
  "exclusive discount",
  "extra discount",
  "instant discount",
  "limited discount",
  "huge discount",
  "massive discount",
  "big discount",
  "additional discount",
  "seasonal discount",
  "festival discount",
  "early bird discount",
  "coupon",
  "coupon code",
  "promo code",
  "promotional code",
  "voucher",
  "voucher code",
  "gift voucher",
  "gift card",
  "free voucher",
  "cashback voucher",
  "redeem coupon",
  "redeem voucher",
  "use coupon",
  "apply coupon",
  "claim coupon",

  // =========================
  // SALES / SHOPPING
  // =========================
  "sale",
  "big sale",
  "mega sale",
  "flash sale",
  "clearance sale",
  "season sale",
  "seasonal sale",
  "holiday sale",
  "festival sale",
  "exclusive sale",
  "members sale",
  "private sale",
  "online sale",
  "shopping sale",
  "store sale",
  "warehouse sale",
  "stock clearance",
  "clearance",
  "price drop",
  "price reduced",
  "reduced price",
  "lower price",
  "lowest price",
  "best price",
  "special price",
  "special pricing",
  "buy now",
  "shop now",
  "order now",
  "shop today",
  "order today",
  "start shopping",
  "browse products",
  "new arrivals",
  "new collection",
  "trending products",
  "popular products",
  "bestsellers",
  "best sellers",
  "recommended products",

  // =========================
  // FREE / GIVEAWAY
  // =========================
  "free",
  "free gift",
  "free reward",
  "free sample",
  "free trial",
  "free product",
  "free item",
  "free delivery",
  "free shipping",
  "free upgrade",
  "free access",
  "free membership",
  "free subscription",
  "free bonus",
  "free credit",
  "free points",
  "free cash",
  "free money",
  "free entry",
  "free giveaway",
  "free contest",
  "giveaway",
  "give away",
  "gift",
  "complimentary gift",
  "complimentary item",
  "bonus gift",
  "surprise gift",
  "exclusive gift",
  "claim your gift",
  "claim free gift",
  "get your free gift",

  // =========================
  // REWARDS / LOYALTY
  // =========================
  "reward",
  "rewards",
  "reward points",
  "bonus points",
  "loyalty points",
  "loyalty reward",
  "loyalty bonus",
  "member rewards",
  "membership reward",
  "customer reward",
  "customer bonus",
  "special reward",
  "exclusive reward",
  "cashback",
  "cash back",
  "cashback offer",
  "cashback reward",
  "cashback bonus",
  "instant cashback",
  "extra cashback",
  "reward balance",
  "points balance",
  "points available",
  "redeem points",
  "redeem rewards",
  "redeem your points",
  "use your points",
  "bonus available",

  // =========================
  // PRIZES / CONTESTS
  // =========================
  "congratulations",
  "congratulation",
  "you won",
  "you have won",
  "you are a winner",
  "you've won",
  "winner",
  "lucky winner",
  "selected winner",
  "selected as a winner",
  "prize",
  "prize winner",
  "grand prize",
  "cash prize",
  "bonus prize",
  "exclusive prize",
  "reward prize",
  "contest",
  "contest winner",
  "competition",
  "competition winner",
  "lucky draw",
  "lucky draw winner",
  "draw winner",
  "raffle",
  "raffle winner",
  "sweepstakes",
  "sweepstakes winner",
  "lottery",
  "lottery winner",
  "jackpot",
  "jackpot winner",
  "winning ticket",
  "winning number",
  "prize claim",
  "claim your prize",
  "claim prize",
  "collect your prize",
  "collect reward",

  // =========================
  // MONEY / CASH PROMOTIONS
  // =========================
  "cash bonus",
  "cash reward",
  "cash offer",
  "money bonus",
  "money reward",
  "bonus money",
  "instant cash",
  "easy money",
  "extra income",
  "additional income",
  "earn money",
  "earn cash",
  "make money",
  "make extra money",
  "passive income",
  "income opportunity",
  "earning opportunity",
  "financial opportunity",
  "special payout",
  "bonus payout",
  "cash payout",
  "instant payout",
  "payout available",

  // =========================
  // TRIALS / SUBSCRIPTIONS
  // =========================
  "free trial",
  "trial offer",
  "trial period",
  "trial membership",
  "trial subscription",
  "limited trial",
  "extended trial",
  "premium trial",
  "upgrade offer",
  "premium upgrade",
  "free upgrade",
  "exclusive access",
  "premium access",
  "premium membership",
  "special membership",
  "membership offer",
  "subscription offer",
  "subscription deal",
  "limited subscription",
  "special subscription",

  // =========================
  // BUSINESS / MARKETING
  // =========================
  "business opportunity",
  "business offer",
  "business deal",
  "investment opportunity",
  "investment offer",
  "partnership opportunity",
  "partnership offer",
  "affiliate opportunity",
  "affiliate program",
  "affiliate offer",
  "marketing opportunity",
  "marketing campaign",
  "promotional campaign",
  "lead generation",
  "special campaign",
  "exclusive campaign",
  "customer acquisition",
  "grow your business",
  "grow your sales",
  "increase your sales",
  "increase revenue",
  "boost sales",
  "boost revenue",
  "special pricing",
  "bulk discount",
  "wholesale offer",
  "business discount",

  // =========================
  // SURVEYS / FEEDBACK
  // =========================
  "survey",
  "survey invitation",
  "customer survey",
  "customer feedback",
  "feedback request",
  "share your feedback",
  "tell us what you think",
  "complete survey",
  "take survey",
  "participate in survey",
  "survey reward",
  "survey bonus",
  "survey prize",
  "feedback reward",
  "feedback bonus",
  "opinion survey",
  "quick survey",
  "short survey",
  "customer opinion",
  "research survey",

  // =========================
  // SOCIAL / ENGAGEMENT BAIT
  // =========================
  "you've been selected",
  "you have been selected",
  "selected for",
  "chosen for",
  "special invitation",
  "exclusive invitation",
  "invitation only",
  "you're invited",
  "you are invited",
  "join now",
  "join today",
  "sign up now",
  "register now",
  "participate now",
  "act now",
  "don't miss",
  "do not miss",
  "don't miss out",
  "do not miss out",
  "limited availability",
  "limited spots",
  "limited seats",
  "while supplies last",
  "while stocks last",

  // =========================
  // URGENCY USED IN SPAM
  // =========================
  "limited time",
  "limited time only",
  "ends soon",
  "ending soon",
  "offer ends",
  "sale ends",
  "expires soon",
  "last chance",
  "final chance",
  "last opportunity",
  "today only",
  "one day only",
  "this weekend only",
  "available today",
  "available now",
  "act quickly",
  "hurry",
  "hurry up",
  "don't wait",
  "do not wait",
  "get it now",
  "grab it now",
  "claim it now",
  "claim now",
  "redeem now",

  // =========================
  // DELIVERY / SHIPPING PROMOTIONS
  // =========================
  "free shipping",
  "free delivery",
  "express delivery",
  "express shipping",
  "discounted shipping",
  "shipping offer",
  "delivery offer",
  "delivery discount",
  "shipping discount",
  "same day delivery",
  "next day delivery",
  "special delivery offer",

  // =========================
  // APP / SERVICE PROMOTIONS
  // =========================
  "download now",
  "install now",
  "try now",
  "try for free",
  "start for free",
  "get started for free",
  "upgrade now",
  "activate offer",
  "unlock offer",
  "unlock reward",
  "unlock bonus",
  "unlock access",
  "exclusive access",
  "early access",
  "beta access",
  "special access",

  // =========================
  // COMMON SPAM PHRASES
  // =========================
  "act fast",
  "act immediately",
  "don't miss this",
  "do not miss this",
  "once in a lifetime",
  "best deal",
  "deal expires",
  "offer expires",
  "special opportunity",
  "rare opportunity",
  "unique opportunity",
  "exclusive opportunity",
  "incredible opportunity",
  "amazing opportunity",
  "limited availability",
  "limited quantity",
  "only a few left",
  "few items left",
  "selling fast",
  "going fast",
  "popular choice",
  "high demand",
  "customer favorite",
  "best seller",
  "top rated",

  // =========================
  // AD / MARKETING LANGUAGE
  // =========================
  "advertisement",
  "advertising",
  "sponsored offer",
  "sponsored deal",
  "promoted offer",
  "promoted deal",
  "marketing message",
  "promotional message",
  "special announcement",
  "commercial offer",
  "commercial promotion",
  "brand promotion",
  "product promotion",
  "service promotion",
  "customer promotion",

  // =========================
  // COMMON SPAM CTA PHRASES
  // =========================
  "click here",
  "click below",
  "click to claim",
  "click to redeem",
  "click to receive",
  "click to get",
  "learn more",
  "get offer",
  "get deal",
  "get discount",
  "get reward",
  "get bonus",
  "claim offer",
  "claim deal",
  "claim reward",
  "claim bonus",
  "redeem offer",
  "redeem deal",
  "redeem reward",
  "redeem bonus"
];

const urgencyKeywords = [

    // =========================
    // BASIC URGENCY
    // =========================
    "urgent",
    "urgently",
    "immediately",
    "immediate action",
    "immediate response",
    "immediate attention",
    "action required",
    "response required",
    "attention required",
    "action needed",
    "response needed",
    "attention needed",
    "required action",
    "important action",
    "critical action",
    "critical response",
    "critical notice",
    "high priority",
    "priority action",
    "priority notice",
    "time sensitive",
    "time-sensitive",
    "time critical",
    "time-critical",

    // =========================
    // FINAL WARNING / NOTICE
    // =========================
    "final warning",
    "final notice",
    "final reminder",
    "last warning",
    "last notice",
    "last reminder",
    "last chance",
    "final chance",
    "important warning",
    "urgent warning",
    "critical warning",
    "important notice",
    "urgent notice",
    "critical notice",

    // =========================
    // DEADLINES
    // =========================
    "deadline",
    "strict deadline",
    "response deadline",
    "payment deadline",
    "verification deadline",
    "account deadline",
    "security deadline",
    "deadline approaching",
    "deadline is approaching",
    "before the deadline",
    "before deadline",
    "past the deadline",
    "deadline has passed",
    "meet the deadline",
    "complete before deadline",
    "respond before deadline",
    "act before deadline",
    "due today",
    "payment due today",
    "response due today",
    "verification due today",
    "action due today",

    // =========================
    // EXPIRATION
    // =========================
    "expires today",
    "expire today",
    "expiration today",
    "expires soon",
    "expire soon",
    "expiring soon",
    "expiration soon",
    "access expires",
    "account expires",
    "service expires",
    "subscription expires",
    "link expires",
    "verification expires",
    "offer expires",
    "before expiration",
    "before expiry",
    "before it expires",
    "before access expires",
    "before account expires",

    // =========================
    // TIME WINDOWS
    // =========================
    "within 1 hour",
    "within one hour",
    "within 2 hours",
    "within two hours",
    "within 6 hours",
    "within six hours",
    "within 12 hours",
    "within twelve hours",
    "within 24 hours",
    "within twenty four hours",
    "within twenty-four hours",
    "within 48 hours",
    "within forty eight hours",
    "within forty-eight hours",
    "within an hour",
    "within a few hours",
    "within one day",
    "within 1 day",
    "within two days",
    "within 2 days",
    "within a day",

    // =========================
    // IMMEDIATE ACTION
    // =========================
    "act now",
    "respond now",
    "reply now",
    "verify now",
    "confirm now",
    "update now",
    "login now",
    "log in now",
    "sign in now",
    "pay now",
    "send now",
    "transfer now",
    "submit now",
    "complete now",
    "do this now",
    "take action now",
    "take immediate action",
    "take action immediately",
    "please act immediately",
    "please respond immediately",
    "please verify immediately",
    "please confirm immediately",
    "please update immediately",
    "please send immediately",
    "please transfer immediately",

    // =========================
    // DELAY / WAIT
    // =========================
    "do not delay",
    "don't delay",
    "do not wait",
    "don't wait",
    "without delay",
    "without further delay",
    "without waiting",
    "do not postpone",
    "don't postpone",
    "do not ignore",
    "don't ignore",
    "do not ignore this message",
    "do not ignore this warning",
    "do not ignore this notice",

    // =========================
    // ASAP
    // =========================
    "as soon as possible",
    "asap",
    "at once",
    "right away",
    "straight away",
    "as quickly as possible",
    "as fast as possible",
    "without delay",
    "immediately",

    // ==================================================
    // DAILY-LIFE SOCIAL ENGINEERING
    // ==================================================

    // -------------------------
    // FAMILY EMERGENCY
    // -------------------------
    "family emergency",
    "family emergency situation",
    "urgent family matter",
    "urgent family emergency",
    "emergency at home",
    "emergency at the hospital",
    "hospital emergency",
    "medical emergency",
    "urgent medical situation",
    "someone needs help urgently",
    "we need help urgently",
    "please help urgently",
    "need help immediately",
    "need your help immediately",
    "need your help urgently",
    "please help me now",
    "help me right away",
    "help immediately",
    "send help immediately",

    // -------------------------
    // FRIEND / RELATIVE MONEY
    // -------------------------
    "send me money",
    "send money",
    "send money urgently",
    "send money immediately",
    "send money now",
    "transfer money",
    "transfer money now",
    "transfer money immediately",
    "transfer the money",
    "transfer it now",
    "transfer it immediately",
    "please transfer",
    "please send money",
    "please send the money",
    "please send it",
    "please pay for me",
    "pay for me",
    "make the payment for me",
    "make payment for me",
    "can you send money",
    "can you transfer money",
    "can you pay",
    "i need money urgently",
    "i need money immediately",
    "i need money now",
    "i need the money urgently",
    "i need the money immediately",
    "i need the money today",
    "i need your help financially",
    "i need financial help",

    // -------------------------
    // EMERGENCY MONEY REQUESTS
    // -------------------------
    "emergency payment",
    "urgent payment",
    "urgent payment request",
    "emergency payment request",
    "immediate payment",
    "immediate payment required",
    "payment needed urgently",
    "payment needed immediately",
    "payment needed today",
    "money needed urgently",
    "money needed immediately",
    "money needed today",
    "funds needed urgently",
    "funds needed immediately",
    "funds needed today",
    "cash needed urgently",
    "cash needed immediately",
    "cash needed today",

    // -------------------------
    // TRAVEL / STRANDED
    // -------------------------
    "i am stranded",
    "i'm stranded",
    "stuck somewhere",
    "i am stuck",
    "i'm stuck",
    "stuck at the airport",
    "stuck at the station",
    "stuck at a hotel",
    "stuck while traveling",
    "travel emergency",
    "travel emergency situation",
    "need money for travel",
    "need money for a ticket",
    "need money for a taxi",
    "need money for transport",
    "need money to get home",
    "need help getting home",
    "send money for my ticket",
    "send money for a ticket",
    "pay for my ticket",
    "pay for my transport",
    "pay for my hotel",
    "pay the hotel bill",
    "urgent travel payment",

    // -------------------------
    // PHONE / NUMBER CHANGE
    // -------------------------
    "i changed my number",
    "my number changed",
    "this is my new number",
    "new phone number",
    "new mobile number",
    "contact me on this number",
    "my phone is not working",
    "my phone is broken",
    "i lost my phone",
    "my phone was lost",
    "i cannot access my phone",
    "i cannot access my old number",
    "use this number instead",
    "please save this number",
    "please update my number",

    // -------------------------
    // DON'T CALL / DON'T VERIFY
    // -------------------------
    "do not call me",
    "don't call me",
    "please don't call",
    "do not call",
    "don't contact me",
    "do not contact me",
    "cannot talk right now",
    "can't talk right now",
    "i cannot talk right now",
    "i can't talk right now",
    "i am unable to talk",
    "i cannot answer the phone",
    "i can't answer the phone",
    "just send it",
    "just transfer it",
    "just make the payment",
    "just pay it",
    "no need to call",
    "no need to contact me",
    "no need to verify",

    // -------------------------
    // CONFIDENTIALITY / SECRECY
    // -------------------------
    "keep this confidential",
    "keep this private",
    "keep this between us",
    "keep this a secret",
    "please keep this confidential",
    "please keep this private",
    "do not tell anyone",
    "don't tell anyone",
    "do not tell anyone about this",
    "don't tell anyone about this",
    "do not discuss this",
    "don't discuss this",
    "do not share this",
    "don't share this",
    "do not mention this",
    "don't mention this",
    "keep this discreet",
    "this is confidential",
    "this is private",
    "this is sensitive",

    // -------------------------
    // BOSS / CEO / MANAGER
    // -------------------------
    "urgent request from your manager",
    "urgent request from your boss",
    "urgent request from the manager",
    "urgent request from the boss",
    "urgent request from the ceo",
    "urgent request from ceo",
    "request from the ceo",
    "request from your ceo",
    "request from your boss",
    "request from your manager",
    "boss needs this urgently",
    "manager needs this urgently",
    "ceo needs this urgently",
    "boss needs the payment",
    "manager needs the payment",
    "ceo needs the payment",
    "boss needs money",
    "manager needs money",
    "ceo needs money",
    "director needs this urgently",
    "executive needs this urgently",
    "send the payment to the client",
    "pay the vendor immediately",
    "pay the supplier immediately",
    "transfer to the vendor",
    "transfer to the supplier",
    "make this payment immediately",
    "complete this transfer immediately",

    // -------------------------
    // WORKPLACE PRESSURE
    // -------------------------
    "urgent work request",
    "urgent business request",
    "urgent business matter",
    "urgent office matter",
    "urgent company matter",
    "urgent client request",
    "urgent client payment",
    "urgent vendor payment",
    "urgent supplier payment",
    "urgent invoice payment",
    "payment required before meeting",
    "payment required before the meeting",
    "complete before the meeting",
    "send before the meeting",
    "transfer before the meeting",
    "need this before the meeting",
    "need this today",
    "need this immediately",
    "need this urgently",
    "please handle this urgently",

    // -------------------------
    // INVOICE / BILL PRESSURE
    // -------------------------
    "bill is due today",
    "invoice is due today",
    "invoice payment due",
    "urgent invoice",
    "urgent invoice payment",
    "overdue invoice",
    "overdue bill",
    "overdue payment",
    "payment overdue",
    "bill overdue",
    "pay the bill immediately",
    "pay the invoice immediately",
    "settle the invoice immediately",
    "settle the bill immediately",
    "payment must be made today",
    "invoice must be paid today",
    "bill must be paid today",

    // ==================================================
    // MONEY TRANSFER / PAYMENT SOCIAL ENGINEERING
    // ==================================================
    "send the payment",
    "send payment now",
    "send payment immediately",
    "send payment urgently",
    "transfer the payment",
    "transfer payment now",
    "transfer payment immediately",
    "make the transfer",
    "make the transfer now",
    "make the transfer immediately",
    "complete the transfer",
    "complete the transfer now",
    "complete the transfer immediately",
    "authorize the transfer",
    "authorize the transfer now",
    "authorize the payment",
    "authorize the payment immediately",
    "pay immediately",
    "pay now",
    "pay today",
    "send funds",
    "send funds now",
    "send funds immediately",
    "transfer funds",
    "transfer funds now",
    "transfer funds immediately",
    "release the funds",
    "release funds immediately",

    // ==================================================
    // PAYMENT METHOD / BANKING URGENCY
    // ==================================================
    "urgent bank transfer",
    "urgent bank payment",
    "urgent wire transfer",
    "urgent transfer request",
    "immediate bank transfer",
    "immediate wire transfer",
    "bank transfer required",
    "bank transfer required today",
    "bank transfer required immediately",
    "wire transfer required",
    "wire transfer required today",
    "wire transfer required immediately",
    "payment authorization required",
    "payment authorization required immediately",
    "transaction authorization required",
    "transaction authorization required immediately",

    // ==================================================
    // OTP / CODE URGENCY
    // ==================================================
    "send the otp now",
    "send otp now",
    "send your otp now",
    "provide otp immediately",
    "provide your otp immediately",
    "share otp immediately",
    "share your otp immediately",
    "enter otp immediately",
    "enter your otp immediately",
    "send the code now",
    "send verification code now",
    "send the verification code now",
    "provide verification code immediately",
    "provide the verification code immediately",
    "share verification code immediately",
    "share the verification code immediately",
    "send security code now",
    "send the security code now",
    "provide security code immediately",
    "provide the security code immediately",

    // ==================================================
    // ACCOUNT SECURITY
    // ==================================================
    "account suspended",
    "account will be suspended",
    "account may be suspended",
    "account locked",
    "account will be locked",
    "account may be locked",
    "account blocked",
    "account will be blocked",
    "account may be blocked",
    "account restricted",
    "account will be restricted",
    "account may be restricted",
    "account disabled",
    "account will be disabled",
    "account may be disabled",
    "account terminated",
    "account will be terminated",
    "account may be terminated",
    "account closed",
    "account will be closed",
    "account may be closed",
    "avoid suspension",
    "avoid closure",
    "avoid termination",
    "avoid account lock",
    "restore access",
    "regain access",
    "unlock account",
    "unlock your account",
    "reactivate account",
    "reactivate your account",

    // ==================================================
    // VERIFICATION URGENCY
    // ==================================================
    "verify immediately",
    "verify urgently",
    "verify today",
    "verify now",
    "verify within 24 hours",
    "verify within 48 hours",
    "verify before deadline",
    "verify before expiration",
    "verify before suspension",
    "verify before closure",
    "confirm immediately",
    "confirm urgently",
    "confirm today",
    "confirm now",
    "confirm within 24 hours",
    "confirm within 48 hours",
    "confirm before deadline",
    "confirm before expiration",
    "confirm before suspension",
    "confirm before closure",

    // ==================================================
    // UPDATE URGENCY
    // ==================================================
    "update immediately",
    "update urgently",
    "update today",
    "update now",
    "update within 24 hours",
    "update within 48 hours",
    "update before deadline",
    "update before expiration",
    "update before suspension",
    "update before closure",
    "update your account immediately",
    "update your account now",
    "update your information immediately",
    "update your information now",
    "update payment information immediately",
    "update payment information now",

    // ==================================================
    // FAILURE TO ACT
    // ==================================================
    "failure to respond",
    "failure to act",
    "failure to verify",
    "failure to confirm",
    "failure to update",
    "failure to comply",
    "if you fail to respond",
    "if you fail to act",
    "if you fail to verify",
    "if you fail to confirm",
    "if you fail to update",
    "if you do not respond",
    "if you do not act",
    "if you do not verify",
    "if you do not confirm",
    "if you do not update",
    "if you don't respond",
    "if you don't act",
    "if you don't verify",
    "if you don't confirm",

    // ==================================================
    // CONSEQUENCES
    // ==================================================
    "your account will be suspended",
    "your account may be suspended",
    "your account will be locked",
    "your account may be locked",
    "your account will be closed",
    "your account may be closed",
    "your account will be deleted",
    "your account may be deleted",
    "your account will be terminated",
    "your account may be terminated",
    "your access will be blocked",
    "your access may be blocked",
    "your access will be restricted",
    "your access may be restricted",
    "your access will be revoked",
    "your access may be revoked",
    "your service will be suspended",
    "your service may be suspended",
    "your service will be terminated",
    "your service may be terminated",

    // ==================================================
    // COUNTDOWN / PRESSURE
    // ==================================================
    "one day remaining",
    "one day left",
    "1 day remaining",
    "1 day left",
    "few hours remaining",
    "few hours left",
    "hours remaining",
    "hours left",
    "minutes remaining",
    "minutes left",
    "only hours remaining",
    "only hours left",
    "only minutes remaining",
    "only minutes left",
    "time is running out",
    "running out of time",
    "countdown",
    "countdown has started",
    "closing soon",
    "ending soon",
    "ends today",
    "ending today",
    "ends shortly",
    "ending shortly",

    // ==================================================
    // GENERAL MONEY-REQUEST PRESSURE
    // ==================================================
    "please don't ask questions",
    "don't ask questions",
    "no questions please",
    "just do it",
    "please do it quickly",
    "please do this quickly",
    "please send it quickly",
    "please transfer it quickly",
    "please pay it quickly",
    "need this done quickly",
    "need this completed quickly",
    "need this handled quickly",
    "this cannot wait",
    "this can't wait",
    "there is no time",
    "we don't have time",
    "we have very little time",
    "i don't have time",
    "i have very little time",
    "please hurry",
    "hurry",
    "hurry up",
    "need it right away",
    "need it now",
    "need it immediately",
    "need it urgently",

    // ==================================================
    // COMPLIANCE / MANDATORY
    // ==================================================
    "mandatory action",
    "mandatory response",
    "mandatory verification",
    "mandatory confirmation",
    "mandatory update",
    "mandatory payment",
    "compliance required",
    "compliance action required",
    "compliance response required",
    "compliance verification required",
    "regulatory action required",
    "regulatory response required",
    "regulatory verification required",
    "required for compliance",
    "security compliance required",

    // ==================================================
    // DAILY-LIFE DEADLINES
    // ==================================================
    "before 5 pm",
    "before 6 pm",
    "before 7 pm",
    "before 8 pm",
    "before tonight",
    "before tomorrow",
    "before morning",
    "by tonight",
    "by tomorrow",
    "by morning",
    "by the end of today",
    "before the end of today",
    "before midnight",
    "by midnight",
    "tonight only",
    "today only",
    "need it by tonight",
    "need it by tomorrow",
    "need the payment by tonight",
    "need the payment by tomorrow",
    "send it before tonight",
    "transfer it before tonight",
    "pay it before tonight"
];

const credentialKeywords = [
  // =========================
  // LOGIN / ACCOUNT CREDENTIALS
  // =========================
  "login credentials",
  "account credentials",
  "user credentials",
  "user login",
  "login details",
  "account login details",
  "login information",
  "account information",
  "login data",
  "account login",
  "login authentication",
  "account authentication",
  "user authentication",
  "login verification",
  "account verification",

  "username",
  "user name",
  "user id",
  "userid",
  "login id",
  "login username",
  "account username",
  "account user id",
  "user identification",
  "login identity",
  "account identity",
  "member id",
  "customer id",
  "client id",
  "employee id",

  "username and password",
  "username/password",
  "user id and password",
  "user id/password",
  "login id and password",
  "login id/password",
  "account id and password",
  "account username and password",
  "user name and password",
  "user name/password",
  "email and password",
  "email/password",
  "login name and password",
  "login credentials required",
  "credentials required",

  "enter your username",
  "enter username",
  "enter your user id",
  "enter user id",
  "enter your login id",
  "enter login id",
  "enter your account id",
  "enter account id",
  "enter your login name",
  "enter login name",
  "provide your username",
  "provide username",
  "provide your user id",
  "provide user id",
  "provide your login id",
  "provide login id",

  // =========================
  // PASSWORD
  // =========================
  "password",
  "account password",
  "login password",
  "user password",
  "current password",
  "old password",
  "new password",
  "temporary password",
  "one time password",
  "one-time password",
  "one time passcode",
  "one-time passcode",
  "temporary login password",
  "temporary access password",
  "account login password",
  "user login password",
  "online password",
  "portal password",
  "service password",
  "member password",

  "enter your password",
  "enter password",
  "enter the password",
  "enter your account password",
  "enter account password",
  "enter your login password",
  "enter login password",
  "provide your password",
  "provide password",
  "provide the password",
  "provide your account password",
  "submit your password",
  "submit password",
  "submit the password",
  "submit your account password",
  "confirm your password",
  "confirm password",
  "confirm the password",
  "confirm your account password",
  "verify your password",

  "re-enter your password",
  "reenter your password",
  "re enter your password",
  "type your password",
  "type password",
  "input your password",
  "input password",
  "update your password",
  "change your password",
  "reset your password",
  "recover your password",
  "restore your password",
  "validate your password",
  "authenticate your password",
  "password verification",
  "password confirmation",
  "password authentication",
  "password validation",
  "password check",
  "password required",

  // =========================
  // SECURITY CODES / TOKENS
  // =========================
  "security code",
  "security verification code",
  "security number",
  "security token",
  "security key",
  "security credential",
  "security credentials",
  "security verification",
  "security authentication",
  "security confirmation",
  "security validation",
  "security check",
  "security passcode",
  "security pass phrase",
  "security passphrase",
  "security identifier",
  "security response",
  "security answer",
  "security question",
  "security challenge",

  "verification code",
  "verification number",
  "verification token",
  "verification key",
  "verification passcode",
  "verification password",
  "verification phrase",
  "verification identifier",
  "verification response",
  "verification value",
  "verification credential",
  "verification credentials",
  "verification details",
  "verification information",
  "verification data",
  "account verification code",
  "account verification number",
  "account verification token",
  "account verification key",
  "account verification passcode",

  // =========================
  // AUTHENTICATION
  // =========================
  "authentication code",
  "authentication number",
  "authentication token",
  "authentication key",
  "authentication passcode",
  "authentication password",
  "authentication phrase",
  "authentication identifier",
  "authentication response",
  "authentication value",
  "authentication credential",
  "authentication credentials",
  "authentication details",
  "authentication information",
  "authentication data",
  "account authentication code",
  "account authentication token",
  "account authentication key",
  "login authentication code",
  "login authentication token",

  "auth code",
  "auth token",
  "auth key",
  "auth passcode",
  "auth password",
  "auth credentials",
  "auth credential",
  "auth verification",
  "authenticator code",
  "authenticator token",
  "authenticator key",
  "authenticator password",
  "authenticator verification",
  "authenticator passcode",
  "authenticator credentials",
  "authentication challenge",
  "authentication request",
  "authentication confirmation",

  // =========================
  // CONFIRMATION
  // =========================
  "confirmation code",
  "confirmation number",
  "confirmation token",
  "confirmation key",
  "confirmation passcode",
  "confirmation password",
  "confirmation credential",
  "confirmation credentials",
  "confirmation details",
  "confirmation information",
  "confirmation data",
  "account confirmation code",
  "account confirmation number",
  "account confirmation token",
  "account confirmation key",
  "account confirmation passcode",
  "account confirmation password",
  "login confirmation code",
  "login confirmation token",
  "login confirmation request",

  // =========================
  // ACCESS
  // =========================
  "access code",
  "access token",
  "access key",
  "access passcode",
  "access password",
  "access credential",
  "access credentials",
  "access verification",
  "access authentication",
  "access confirmation",
  "access details",
  "access information",
  "access data",
  "account access code",
  "account access token",
  "account access key",
  "account access password",
  "account access credentials",
  "login access code",
  "login access token",

  // =========================
  // OTP / ONE-TIME CODES
  // =========================
  "one time code",
  "one-time code",
  "one time verification",
  "one-time verification",
  "one time authentication",
  "one-time authentication",
  "one time token",
  "one-time token",
  "single use password",
  "single-use password",
  "single use passcode",
  "single-use passcode",
  "temporary verification code",
  "temporary authentication code",
  "temporary access code",
  "temporary security code",

  "otp",
  "otp code",
  "otp number",
  "otp token",
  "otp password",
  "otp passcode",
  "otp verification",
  "otp authentication",
  "otp confirmation",
  "otp security code",
  "otp security token",
  "otp credential",
  "otp credentials",
  "otp request",
  "otp required",
  "otp verification required",
  "otp authentication required",
  "otp confirmation required",
  "otp validation",
  "otp check",

  "enter otp",
  "enter the otp",
  "enter your otp",
  "enter otp code",
  "enter the otp code",
  "enter your otp code",
  "provide otp",
  "provide the otp",
  "provide your otp",
  "provide otp code",
  "provide the otp code",
  "submit otp",
  "submit the otp",
  "submit your otp",
  "submit otp code",
  "confirm otp",
  "confirm the otp",
  "confirm your otp",
  "verify otp",
  "verify the otp",

  "send otp",
  "send the otp",
  "send your otp",
  "share otp",
  "share the otp",
  "share your otp",
  "forward otp",
  "forward the otp",
  "reply with otp",
  "reply with the otp",
  "return otp",
  "return the otp",

  "provide verification code",
  "provide the verification code",
  "send verification code",
  "send the verification code",
  "share verification code",
  "share the verification code",
  "submit verification code",
  "submit the verification code",
  "enter verification code",
  "enter the verification code",

  "send security code",
  "send the security code",
  "share security code",
  "share the security code",
  "provide security code",
  "provide the security code",
  "submit security code",
  "submit the security code",

  // =========================
  // PIN
  // =========================
  "pin",
  "pin code",
  "security pin",
  "account pin",
  "login pin",
  "verification pin",
  "authentication pin",
  "access pin",
  "transaction pin",
  "banking pin",
  "card pin",
  "atm pin",
  "online banking pin",
  "mobile banking pin",
  "payment pin",
  "payment security pin",
  "account security pin",
  "user pin",
  "customer pin",
  "member pin",

  "enter pin",
  "enter the pin",
  "enter your pin",
  "enter pin code",
  "enter your pin code",
  "provide pin",
  "provide the pin",
  "provide your pin",
  "submit pin",
  "submit the pin",
  "submit your pin",
  "confirm pin",
  "confirm the pin",
  "confirm your pin",
  "verify pin",
  "verify the pin",
  "verify your pin",
  "send pin",
  "share pin",
  "provide pin code",

  // =========================
  // CREDIT CARD
  // =========================
  "credit card number",
  "credit card details",
  "credit card information",
  "credit card data",
  "credit card credentials",
  "credit card security",
  "credit card verification",
  "credit card authentication",
  "credit card confirmation",
  "credit card payment details",
  "credit card billing details",
  "credit card account details",
  "credit card identification",
  "credit card validation",
  "credit card number required",
  "credit card details required",
  "credit card information required",
  "credit card verification required",
  "credit card authentication required",
  "credit card confirmation required",

  // =========================
  // DEBIT CARD
  // =========================
  "debit card number",
  "debit card details",
  "debit card information",
  "debit card data",
  "debit card credentials",
  "debit card security",
  "debit card verification",
  "debit card authentication",
  "debit card confirmation",
  "debit card payment details",
  "debit card billing details",
  "debit card account details",
  "debit card identification",
  "debit card validation",
  "debit card number required",
  "debit card details required",
  "debit card information required",
  "debit card verification required",
  "debit card authentication required",
  "debit card confirmation required",

  // =========================
  // GENERAL CARD INFORMATION
  // =========================
  "card number",
  "card details",
  "card information",
  "card data",
  "card credentials",
  "card security",
  "card verification",
  "card authentication",
  "card confirmation",
  "card payment details",
  "card billing details",
  "card account details",
  "card identification",
  "card validation",
  "card number required",
  "card details required",
  "card information required",
  "card verification required",
  "card authentication required",
  "card confirmation required",

  "cardholder name",
  "card holder name",
  "cardholder information",
  "card holder information",
  "cardholder details",
  "card holder details",
  "cardholder data",
  "card holder data",
  "card expiry",
  "card expiration",
  "card expiration date",
  "card expiry date",
  "expiry date",
  "expiration date",
  "expiration month",
  "expiration year",
  "expiry month",
  "expiry year",
  "valid through",
  "valid thru",

  // =========================
  // CVV / CVC
  // =========================
  "cvv",
  "cvv code",
  "cvv number",
  "cvv2",
  "cvv2 code",
  "cvv2 number",
  "cvc",
  "cvc code",
  "cvc number",
  "cvc2",
  "cvc2 code",
  "cvc2 number",
  "card security code",
  "card security number",
  "card verification code",
  "card verification number",
  "card authentication code",
  "card authentication number",
  "three digit code",
  "3 digit code",
  "three-digit code",
  "four digit code",
  "four-digit code",

  "payment verification code",
  "payment security code",
  "payment authentication code",
  "payment confirmation code",
  "transaction verification code",
  "transaction security code",
  "transaction authentication code",
  "transaction confirmation code",
  "payment credentials",
  "payment information",
  "payment details",
  "payment card details",
  "payment card information",
  "payment card number",

  // =========================
  // BANKING
  // =========================
  "bank account details",
  "bank account information",
  "bank account data",
  "bank account number",
  "banking details",
  "banking information",
  "banking data",
  "banking credentials",
  "banking credential",
  "bank login",
  "bank login details",
  "bank username",
  "bank password",
  "banking username",
  "banking password",
  "account number",
  "account details",
  "account data",

  "routing number",
  "routing code",
  "routing details",
  "routing information",
  "sort code",
  "sort code details",
  "sort code information",
  "ifsc code",
  "ifsc number",
  "ifsc details",
  "swift code",
  "swift number",
  "swift details",
  "swift information",
  "iban",
  "iban number",
  "iban details",
  "iban information",
  "bank identifier",
  "bank identification",

  "online banking details",
  "online banking information",
  "online banking credentials",
  "online banking login",
  "online banking username",
  "online banking password",
  "online banking verification",
  "online banking authentication",
  "online banking security code",
  "online banking access code",

  "mobile banking details",
  "mobile banking information",
  "mobile banking credentials",
  "mobile banking login",
  "mobile banking username",
  "mobile banking password",
  "mobile banking verification",
  "mobile banking authentication",
  "mobile banking security code",
  "mobile banking access code",

  // =========================
  // TRANSACTION / PAYMENT
  // =========================
  "transaction password",
  "transaction pin",
  "transaction code",
  "transaction token",
  "transaction verification",
  "transaction authentication",
  "transaction confirmation",
  "transaction security code",
  "transaction authorization code",
  "transaction authorization",

  "payment password",
  "payment passcode",
  "payment token",
  "payment credential",
  "payment credentials",
  "payment verification",
  "payment authentication",
  "payment confirmation",
  "payment authorization",
  "payment security",

  // =========================
  // GOVERNMENT / TAX / ID
  // =========================
  "social security number",
  "social security details",
  "social security information",
  "social security data",
  "social security id",

  "tax identification number",
  "tax identification",
  "tax id",
  "tax number",
  "tax details",
  "tax information",
  "tax credentials",

  "national id",
  "national identification number",
  "national identification",
  "national id number",
  "government id",
  "government id number",
  "government identification",
  "government identification number",

  // =========================
  // PASSPORT / LICENSE / IDENTITY
  // =========================
  "passport number",
  "passport details",
  "passport information",
  "passport data",
  "passport id",
  "passport identification",
  "passport verification",
  "passport authentication",

  "driving license number",
  "driving licence number",
  "driver license number",
  "driver licence number",
  "driver identification",
  "license number",
  "licence number",

  "identity number",
  "identity details",
  "identity information",
  "identity data",
  "identity credentials",

  "personal identification",
  "personal identification number",
  "personal id",
  "personal id number",
  "personal details",
  "personal information",
  "personal data",
  "personal credentials",

  "identity verification",
  "identity confirmation",
  "identity authentication",
  "identity validation",
  "identity check",
  "identity document",
  "identity document number",
  "id verification",
  "id confirmation",
  "id authentication",
  "id validation",

  // =========================
  // SECURITY / RECOVERY QUESTIONS
  // =========================
  "secret question",
  "secret answer",
  "security question",
  "security answer",
  "recovery question",
  "recovery answer",
  "account recovery question",
  "account recovery answer",
  "password recovery question",
  "password recovery answer",
  "login recovery question",
  "login recovery answer",
  "security challenge question",
  "security challenge answer",
  "account security question",
  "account security answer",
  "verification question",
  "verification answer",
  "authentication question",
  "authentication answer",

  // =========================
  // RECOVERY CODES / KEYS
  // =========================
  "recovery code",
  "recovery codes",
  "account recovery code",
  "account recovery codes",
  "password recovery code",
  "password recovery codes",
  "login recovery code",
  "login recovery codes",
  "backup code",
  "backup codes",
  "backup verification code",
  "backup authentication code",
  "backup security code",
  "recovery token",
  "recovery tokens",
  "recovery key",
  "recovery keys",
  "account recovery key",
  "password recovery key",
  "login recovery key",

  // =========================
  // PRIVATE / SECRET KEYS
  // =========================
  "private key",
  "private keys",
  "secret key",
  "secret keys",
  "access key",
  "access keys",
  "security key",
  "security keys",
  "encryption key",
  "encryption keys",
  "authentication key",
  "authentication keys",
  "account key",
  "account security key",
  "backup key",
  "master key",
  "master password",
  "secret credential",
  "secret credentials",

  // =========================
  // CREDENTIAL REQUESTS
  // =========================
  "send your credentials",
  "send credentials",
  "share your credentials",
  "share credentials",
  "submit your credentials",
  "submit credentials",
  "provide your credentials",
  "provide credentials",
  "enter your credentials",
  "enter credentials",
  "verify your credentials",
  "verify credentials",
  "confirm your credentials",
  "confirm credentials",
  "update your credentials",
  "update credentials",
  "validate your credentials",
  "validate credentials",
  "authenticate your credentials",
  "authenticate credentials",

  // =========================
  // PASSWORD REQUESTS
  // =========================
  "send your password",
  "send password",
  "share your password",
  "share password",
  "provide your password",
  "provide password",
  "submit your password",
  "submit password",
  "enter your password",
  "enter password",
  "verify your password",
  "verify password",
  "confirm your password",
  "confirm password",
  "update your password",
  "update password",
  "validate your password",
  "validate password",
  "authenticate your password",
  "authenticate password",

  // =========================
  // PIN / CARD REQUESTS
  // =========================
  "send your pin",
  "send pin",
  "share your pin",
  "share pin",
  "provide your pin",
  "provide pin",
  "submit your pin",
  "submit pin",
  "enter your pin",
  "enter pin",
  "verify your pin",
  "verify pin",
  "confirm your pin",
  "confirm pin",

  "send your card details",
  "send card details",
  "share your card details",
  "share card details",
  "provide your card details",
  "provide card details",
  "submit card details",
  "submit your card details",
  "enter card details",
  "enter your card details",
  "verify card details",
  "verify your card details",
  "confirm card details",
  "confirm your card details",

  // =========================
  // BANK DETAIL REQUESTS
  // =========================
  "send bank details",
  "send your bank details",
  "share bank details",
  "share your bank details",
  "provide bank details",
  "provide your bank details",
  "submit bank details",
  "submit your bank details",
  "enter bank details",
  "enter your bank details",
  "verify bank details",
  "verify your bank details",

  // =========================
  // VERIFICATION / ACCOUNT ACTION
  // =========================
  "verify your account",
  "confirm your account",
  "validate your account",
  "authenticate your account",
  "verify account",
  "confirm account",
  "validate account",
  "authenticate account",

  "verify your identity",
  "confirm your identity",
  "validate your identity",
  "authenticate your identity",
  "verify identity",
  "confirm identity",
  "validate identity",
  "authenticate identity",

  "complete account verification",
  "complete identity verification",
  "complete security verification",
  "complete authentication",
  "complete verification",

  "account verification required",
  "identity verification required",
  "security verification required",
  "authentication required",
  "additional verification required",
  "additional authentication required",
  "additional security verification",
  "account authentication required",
  "identity authentication required",
  "security authentication required",
  "verification required",
  "validation required",
  "authentication needed",
  "verification needed",
  "identity check required",
  "security check required",
  "account security check",
  "account validation required"
];

const brandVariants = [
  "paypa1","pay-pal","paypaI","paypa1-security","paypal-security",
  "paypal-support","paypal-login","paypal-verify","secure-paypal",
  "paypal-account","paypal-alert","paypal-service","paypal-confirm",
  "paypal-protection",

  "micros0ft","micro-soft","micros0ft-security","microsoft-security",
  "microsoft-support","microsoft-login","microsoft-verify",
  "secure-microsoft","microsoft-account","microsoft-alert",
  "microsoft-office","office365-security","office365-login",
  "microsoft365-security","microsoft365-login",

  "amaz0n","amaz-on","amaz0n-security","amazon-security",
  "amazon-support","amazon-login","amazon-verify","secure-amazon",
  "amazon-account","amazon-alert","amazon-prime","amazon-billing",
  "amazon-payment","amazon-order","amazon-delivery",

  "g00gle","g0ogle","goog1e","google-security","google-support",
  "google-login","google-verify","secure-google","google-account",
  "google-alert","google-drive","google-cloud","gmail-security",
  "gmail-support","gmail-login","gmail-verify",

  "faceb00k","faceb0ok","facebok","facebook-security",
  "facebook-support","facebook-login","facebook-verify",
  "secure-facebook","facebook-account","facebook-alert",
  "facebook-business","facebook-protection",

  "app1e","appIe","appl3","apple-security","apple-support",
  "apple-login","apple-verify","secure-apple","apple-account",
  "apple-alert","icloud-security","icloud-support","icloud-login",
  "icloud-verify",

  "netfl1x","netf1ix","netflix-security","netflix-support",
  "netflix-login","netflix-verify","secure-netflix",
  "netflix-account","netflix-alert","netflix-billing",
  "netflix-payment","netflix-renewal",

  "linkedln","link3din","linkedin-security","linkedin-support",
  "linkedin-login","linkedin-verify","secure-linkedin",
  "linkedin-account","linkedin-alert","linkedin-jobs",

  "dell-support","dell-security","dell-login","dell-verify",
  "secure-dell","dell-account","dell-alert","dell-service",
  "dell-technologies",

  "ad0be","adobe-security","adobe-support","adobe-login",
  "adobe-verify","secure-adobe","adobe-account",

  "dropb0x","dropbox-security","dropbox-support","dropbox-login",
  "dropbox-verify","secure-dropbox","dropbox-account",

  "0ne-drive","onedrive-security","onedrive-support","onedrive-login",
  "onedrive-verify","secure-onedrive","onedrive-account",

  "0utlook","outlook-security","outlook-support","outlook-login",
  "outlook-verify","secure-outlook","outlook-account",

  "y0utube","youtube-security","youtube-support","youtube-login",
  "youtube-verify","secure-youtube","youtube-account",

  "instagr4m","instagram-security","instagram-support",
  "instagram-login","instagram-verify","secure-instagram",
  "instagram-account",

  "tw1tter","twitter-security","twitter-support","twitter-login",
  "twitter-verify","secure-twitter","twitter-account",

  "disc0rd","discord-security","discord-support","discord-login",
  "discord-verify","secure-discord","discord-account",

  "ste4m","steam-security","steam-support","steam-login",
  "steam-verify","secure-steam","steam-account",

  "sp0tify","spotify-security","spotify-support","spotify-login",
  "spotify-verify","secure-spotify","spotify-account",

  "chase-security","chase-support","chase-login","chase-verify",
  "secure-chase","chase-account","chase-alert",

  "wellsfargo-security","wellsfargo-support","wellsfargo-login",
  "wellsfargo-verify","secure-wellsfargo","wellsfargo-account",

  "bankofamerica-security","bankofamerica-support",
  "bankofamerica-login","bankofamerica-verify",
  "secure-bankofamerica","bankofamerica-account",

  "citibank-security","citibank-support","citibank-login",
  "citibank-verify","secure-citibank","citibank-account",

  "hsbc-security","hsbc-support","hsbc-login","hsbc-verify",
  "secure-hsbc","hsbc-account",

  "barclays-security","barclays-support","barclays-login",
  "barclays-verify","secure-barclays","barclays-account",

  // Keep only intentionally suspicious standalone variants
  "paypa1",
  "micros0ft",
  "amaz0n",
  "g00gle",
  "g0ogle",
  "goog1e",
  "faceb00k",
  "faceb0ok",
  "facebok",
  "app1e",
  "appIe",
  "appl3",
  "netfl1x",
  "netf1ix",
  "linkedln",
  "link3din",
  "ad0be",
  "dropb0x",
  "0ne-drive",
  "0utlook",
  "y0utube",
  "instagr4m",
  "tw1tter",
  "disc0rd",
  "ste4m",
  "sp0tify"
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
  const sender = (input.sender || "").toLowerCase().trim();
  const subject = (input.subject || "").toLowerCase().trim();
  const body = (input.body || "").toLowerCase().trim();

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

  /*
   * Context-aware signals
   * ---------------------------------------------------------
   * The old system gave large points to every keyword match.
   * That can overreact to legitimate messages containing words
   * such as "security", "verify", or "account".
   *
   * These signals therefore look for combinations of indicators.
   */
  const hasVerification = /\bverify|verification|confirm|confirmation|authenticate|authentication|validate|validation\b/.test(text);
  const hasThreat = /\b(suspended|suspension|blocked|block|locked|lock|restricted|restriction|terminated|termination|closed|closure|disabled|deactivated|revoked)\b/.test(text);
  const hasCredentialRequest = /\b(password|passcode|otp|one[- ]time password|one[- ]time passcode|cvv|cvc|pin|card details|card number|bank details|bank account|login credentials|username and password)\b/.test(text);
  const hasActionLanguage = /\b(click|follow|use the link|open the link|visit|sign in|log in|login|update|verify|confirm|reset|unlock|reactivate)\b/.test(text);
  const hasTimePressure = matchedUrgency.length > 0;
  const hasMoneyLanguage = /\b(payment|invoice|refund|transfer|transaction|billing|purchase|order|money|cashback)\b/.test(text);

  const hasVerificationLink =
    (hasVerification || hasCredentialRequest) && urlMatches.length > 0;

  const hasThreatPlusAction =
    hasThreat && hasActionLanguage;

  const hasVerificationPlusThreat =
    hasVerification && hasThreat;

  const hasCredentialRequestPlusAction =
    hasCredentialRequest && hasActionLanguage;

  const hasUrgencyPlusAction =
    hasTimePressure && hasActionLanguage;

  /*
   * PHISHING SCORE
   * ---------------------------------------------------------
   * Individual generic words are deliberately weighted less.
   * Strong combinations carry more weight.
   */
  let phishingScore = 0;

  phishingScore += Math.min(matchedPhishing.length, 6) * 7;
  phishingScore += Math.min(matchedUrgency.length, 4) * 3;
  phishingScore += Math.min(matchedCredentials.length, 4) * 6;
  phishingScore += Math.min(suspiciousUrls.length, 3) * 22;

  if (senderLooksOff) {
    phishingScore += 10;
  }

  if (matchedLookalikeBrands.length > 0) {
    phishingScore += 22;
  }

  if (hasVerificationPlusThreat) {
    phishingScore += 24;
  }

  if (hasVerificationLink) {
    phishingScore += 18;
  }

  if (hasCredentialRequestPlusAction) {
    phishingScore += 24;
  }

  if (hasThreatPlusAction) {
    phishingScore += 15;
  }

  if (hasUrgencyPlusAction && hasVerification) {
    phishingScore += 16;
  }

  /*
   * SPAM SCORE
   */
  let spamScore = 0;

  spamScore += Math.min(matchedSpam.length, 7) * 6;

  if (matchedSpam.length >= 2) {
    spamScore += 8;
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
    spamScore += 12;
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

  /*
   * Reduce spam classification when the same words appear in a
   * stronger phishing context.
   */
  if (hasCredentialRequestPlusAction || hasVerificationPlusThreat) {
    spamScore = Math.max(0, spamScore - 10);
  }

  phishingScore = Math.min(97, Math.round(phishingScore));
  spamScore = Math.min(95, Math.round(spamScore));

  /*
   * Classification
   * ---------------------------------------------------------
   * Strong combinations can classify an email even when there
   * are only a few keyword matches. This helps with harder tests.
   */
  let verdict = "legitimate";

  const strongPhishingSignal =
    suspiciousUrls.length > 0 &&
    (
      hasVerification ||
      hasCredentialRequest ||
      hasThreat ||
      hasActionLanguage
    );

  const criticalPhishingSignal =
    hasCredentialRequestPlusAction ||
    hasVerificationPlusThreat ||
    (
      matchedLookalikeBrands.length > 0 &&
      (hasVerification || hasCredentialRequest || suspiciousUrls.length > 0)
    );

  if (
    phishingScore >= 50 ||
    criticalPhishingSignal ||
    (strongPhishingSignal && phishingScore >= 35)
  ) {
    verdict = "phishing";
  } else if (spamScore >= 30) {
    verdict = "spam";
  }

  /*
   * Risk and confidence
   */
  let riskScore = 3;
  let confidence = 95;

  if (verdict === "phishing") {
    riskScore = Math.min(
      97,
      Math.max(
        50,
        phishingScore,
        criticalPhishingSignal ? 65 : 0
      )
    );

    confidence = Math.min(
      99,
      80 +
      Math.min(matchedPhishing.length, 5) * 2 +
      Math.min(matchedCredentials.length, 3) * 3 +
      Math.min(suspiciousUrls.length, 2) * 4 +
      (criticalPhishingSignal ? 7 : 0)
    );
  } else if (verdict === "spam") {
    riskScore = Math.min(95, Math.max(30, 20 + spamScore));

    confidence = Math.min(
      97,
      80 + Math.min(matchedSpam.length, 6) * 2
    );
  } else {
    /*
     * Legitimate risk is intentionally conservative.
     * Generic words such as "security", "account", "verify",
     * "payment", or "update" should not automatically make a
     * normal email high-risk.
     */
    const weakPhishingRisk =
      Math.min(matchedPhishing.length, 4) * 2;

    const weakSpamRisk =
      Math.min(matchedSpam.length, 4) * 2;

    const weakUrgencyRisk =
      Math.min(matchedUrgency.length, 2) * 2;

    const weakCredentialRisk =
      Math.min(matchedCredentials.length, 2) * 3;

    const suspiciousUrlRisk =
      suspiciousUrls.length * 10;

    const senderRisk =
      senderLooksOff ? 6 : 0;

    const brandRisk =
      matchedLookalikeBrands.length > 0 ? 8 : 0;

    const combinedRisk =
      weakPhishingRisk +
      weakSpamRisk +
      weakUrgencyRisk +
      weakCredentialRisk +
      suspiciousUrlRisk +
      senderRisk +
      brandRisk;

    riskScore = Math.min(
      49,
      Math.max(3, Math.round(combinedRisk))
    );

    confidence = Math.min(
      97,
      Math.max(70, 97 - Math.round(riskScore * 0.45))
    );
  }

  /*
   * Detection reasons
   */
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

  if (hasVerificationPlusThreat) {
    reasons.push(
      "Verification language is combined with an account threat"
    );
  }

  if (hasCredentialRequestPlusAction) {
    reasons.push(
      "Credential-related information is requested together with an action"
    );
  }

  if (hasVerificationLink) {
    reasons.push(
      "Verification or credential-related language is paired with a URL"
    );
  }

  if (urlMatches.length === 0) {
    reasons.push("No URLs detected in the email body");
  }

  const indicatorCount =
    matchedPhishing.length +
    matchedSpam.length +
    matchedUrgency.length +
    matchedCredentials.length +
    suspiciousUrls.length +
    (senderLooksOff ? 1 : 0) +
    (matchedLookalikeBrands.length > 0 ? 1 : 0);

  if (verdict === "legitimate") {
    if (indicatorCount === 0) {
      reasons.push(
        "No suspicious phishing, spam, sender, or URL indicators detected"
      );
    } else {
      reasons.push(
        "Some generic indicators were detected, but strong phishing or spam patterns were not found"
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
    const pathname = parsedUrl.pathname.toLowerCase();

    const hasIpAddress =
      /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);

    const hasPunycode = hostname.includes("xn--");

    /*
     * Detect suspicious hostname structures.
     * These are intentionally pattern-based because this is a
     * client-side rule engine, not a live reputation service.
     */
    const suspiciousTerms = [
      "verify-",
      "-verify",
      "verify.",
      "secure-",
      "-secure",
      "secure.",
      "account-",
      "-account",
      "account.",
      "login-",
      "-login",
      "login.",
      "update-",
      "-update",
      "update.",
      "signin-",
      "-signin",
      "signin.",
      "auth-",
      "-auth",
      "auth.",
      "support-",
      "-support",
      "support.",
      "security-",
      "-security",
      "security."
    ];

    const hasSuspiciousTerm = suspiciousTerms.some(function (term) {
      return hostname.includes(term);
    });

    /*
     * Detect a suspicious action path even when the hostname
     * itself looks ordinary.
     */
    const suspiciousPathTerms = [
      "/verify",
      "/verification",
      "/confirm",
      "/confirmation",
      "/login",
      "/signin",
      "/sign-in",
      "/secure",
      "/security",
      "/account",
      "/update",
      "/reset",
      "/unlock",
      "/reactivate",
      "/authenticate",
      "/authentication"
    ];

    const hasSuspiciousPath = suspiciousPathTerms.some(function (term) {
      return pathname === term ||
        pathname.startsWith(`${term}/`) ||
        pathname.includes(`${term}?`);
    });

    /*
     * Long subdomains containing several security/action words
     * are more suspicious than a normal single-word domain.
     */
    const hostnameActionCount = [
      "verify",
      "secure",
      "account",
      "login",
      "signin",
      "update",
      "auth",
      "security",
      "support"
    ].filter(function (term) {
      return hostname.includes(term);
    }).length;

    const hasMultipleActionTerms =
      hostnameActionCount >= 2;

    return (
      hasIpAddress ||
      hasPunycode ||
      hasSuspiciousTerm ||
      hasSuspiciousPath ||
      hasMultipleActionTerms
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

  const parts = sender.split("@");
  const localPart = parts[0] || "";
  const domain = parts[1] || "";

  const hasManyNumbers =
    (localPart.match(/\d/g) || []).length >= 4;

  const hasRepeatedHyphens =
    domain.includes("--");

  const hasSuspiciousDomainPattern =
    domain.startsWith("-") ||
    domain.endsWith("-") ||
    domain.includes("secure-login") ||
    domain.includes("account-verify") ||
    domain.includes("verify-account") ||
    domain.includes("login-secure") ||
    domain.includes("security-alert");

  const hasExcessiveSubdomains =
    domain.split(".").length >= 5;

  const hasVeryLongLocalPart =
    localPart.length > 40;

  return (
    hasManyNumbers ||
    hasRepeatedHyphens ||
    hasSuspiciousDomainPattern ||
    hasExcessiveSubdomains ||
    hasVeryLongLocalPart
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