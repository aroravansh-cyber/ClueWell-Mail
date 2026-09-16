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

const phishingKeywords=[
"verify your account","verify account","verify my account","verify the account","confirm your account","confirm account","confirm my account","confirm the account","validate your account","validate account","authenticate your account","authenticate account","activate your account","reactivate your account","restore your account",
"verify your identity","verify identity","confirm your identity","confirm identity","validate your identity","validate identity","authenticate your identity","authenticate identity","identity verification","identity confirmation","identity validation","identity authentication","identity check","identity verification required","identity confirmation required",
"complete verification","complete the verification","complete account verification","complete identity verification","complete security verification","complete authentication","complete the authentication","finish verification","finish the verification","finish account verification","finish identity verification","verification required","verification is required","verification needed","verification is needed",
"security alert","security notice","security warning","security notification","security message","security update","security incident","security issue","security concern","security problem","security check","security verification","security confirmation","security validation","security authentication","security review","security assessment","security action required",
"unusual activity","unusual account activity","unusual login activity","unusual sign in activity","unusual sign-in activity","unusual transaction","unusual transaction activity","unusual payment activity","unusual access","unusual behavior","unusual behavior detected","unusual activity detected","unusual login detected","unusual sign in detected","unusual access detected",
"suspicious activity","suspicious account activity","suspicious login activity","suspicious sign in activity","suspicious sign-in activity","suspicious transaction","suspicious transaction activity","suspicious payment","suspicious payment activity","suspicious access","suspicious behavior","suspicious activity detected","suspicious login detected","suspicious access detected","suspicious transaction detected",
"unrecognized login","unrecognized sign in","unrecognized sign-in","unrecognized login attempt","unrecognized sign in attempt","unrecognized device","unrecognized device detected","unrecognized browser","unrecognized location","unrecognized location detected","unrecognized session","unrecognized access","unrecognized activity","unrecognized transaction","unrecognized payment",
"unauthorized access","unauthorized login","unauthorized sign in","unauthorized sign-in","unauthorized device","unauthorized activity","unauthorized transaction","unauthorized payment","unauthorized transfer","unauthorized account access","unauthorized account activity","unauthorized attempt","unauthorized login attempt","unauthorized access attempt","unauthorized transaction detected",
"account suspended","account has been suspended","account will be suspended","account may be suspended","account is suspended","account locked","account has been locked","account will be locked","account may be locked","account is locked","account blocked","account has been blocked","account will be blocked","account may be blocked","account is blocked",
"account restricted","account has been restricted","account will be restricted","account may be restricted","account is restricted","account terminated","account has been terminated","account will be terminated","account may be terminated","account is terminated","account disabled","account has been disabled","account will be disabled","account may be disabled","account is disabled",
"account deactivated","account has been deactivated","account will be deactivated","account may be deactivated","account is deactivated","account closed","account has been closed","account will be closed","account may be closed","account is closed","account closure","account termination","account suspension","account restriction","account blocking",
"account will be closed","your account will be closed","your account may be closed","your account is scheduled for closure","your account will be deleted","your account may be deleted","account deletion","account will be removed","your account will be removed","your profile will be removed","your access will be removed","your access will be revoked","your access may be revoked","access will be revoked","access may be revoked",
"action required","immediate action","immediate action required","urgent action required","important action required","critical action required","action needed","immediate response required","urgent response required","response required","verification action required","security action required","account action required","mandatory action","mandatory verification","mandatory confirmation",
"update your information","update account information","update your account information","update personal information","update your personal information","update profile information","update your profile","update account details","update your account details","update personal details","confirm your information","confirm account information","confirm personal information","validate your information","validate account information",
"update payment information","update payment details","update your payment information","update your payment details","confirm payment","confirm your payment","verify payment","verify your payment","validate payment","validate your payment","authenticate payment","authenticate your payment","payment verification","payment confirmation","payment authentication","payment validation","payment information required",
"billing information","update billing information","update your billing information","confirm billing information","verify billing information","billing verification","billing confirmation","billing authentication","billing details required","payment method verification","payment method confirmation","payment method update","update payment method","confirm payment method","verify payment method",
"reset your password","reset password","password reset required","password reset requested","password reset verification","password expires","password expiration","password has expired","password will expire","password may expire","password expired","password update required","update your password","change your password","confirm your new password",
"login attempt","login attempt detected","login attempt blocked","login attempt failed","failed login attempt","multiple login attempts","multiple failed login attempts","recent login attempt","recent sign in attempt","recent sign-in attempt","new login attempt","new sign in","new sign-in","login from new device","login from unknown device","login from unfamiliar device",
"secure your account","secure account","protect your account","protect account","account security required","security verification required","security confirmation required","security update required","security action required","secure your profile","protect your profile","secure your login","secure your access","protect your access","restore account security",
"account recovery","account recovery required","account recovery request","account recovery verification","account recovery confirmation","account recovery link","account recovery process","recover your account","recover account","restore account","restore account access","regain account access","recover account access","reactivate account","reactivate account access",
"click here to verify","click here to confirm","click here to validate","click here to authenticate","click here to secure","click here to restore access","click here to unlock","click here to reactivate","click here to update","click here to reset","click here to recover","click here for verification","click here for confirmation","click here for security verification","click here to continue",
"click the link to verify","click the link to confirm","click the link to validate","click the link to authenticate","click the link to secure","click the link to restore access","click the link to unlock","click the link to reactivate","click the link to update","click the link to reset","click the link to recover","follow the link to verify","follow the link to confirm","follow the link to secure","follow the link to continue",
"verify using the link","verify through the link","confirm using the link","confirm through the link","complete verification using the link","complete verification through the link","use the link to verify","use the link to confirm","use the link to secure your account","use the link to restore access","use the link to unlock your account","use the link to reactivate your account","use the link to update your information","use the link to reset your password",
"within 24 hours","within 48 hours","within 12 hours","within 6 hours","within 2 hours","within 1 hour","within one hour","within two hours","within six hours","within twelve hours","within twenty four hours","within twenty-four hours","within forty eight hours","within forty-eight hours","before 24 hours","before 48 hours","before the deadline","before expiration","before expiry",
"failure to verify","failure to confirm","failure to authenticate","failure to validate","failure to complete verification","failure to update","failure to respond","failure to comply","if you fail to verify","if you fail to confirm","if you fail to respond","if you do not verify","if you do not confirm","if you do not respond","if you don't verify","if you don't confirm","if you don't respond",
"your account will be closed","your account may be closed","your account will be deleted","your account may be deleted","your account will be suspended","your account may be suspended","your account will be locked","your account may be locked","your account will be blocked","your account may be blocked","your account will be restricted","your account may be restricted","your account will be disabled","your account may be disabled","your access will be blocked",
"your access will be restricted","your access may be restricted","your access will be suspended","your access may be suspended","your access will be disabled","your access may be disabled","your access will expire","your access may expire","your service will be suspended","your service may be suspended","your service will be terminated","your service may be terminated","service access restricted","service access blocked","service access suspended",
"verify security information","confirm security information","update security information","security information required","security details required","security verification required","security confirmation required","security credentials required","security credentials verification","account security verification","account security confirmation","account security update","account security check","account protection verification","account protection required",
"verify login information","confirm login information","update login information","login information required","login verification required","login confirmation required","login authentication required","login security verification","login security check","login credentials verification","login credentials required","account credentials verification","account credentials required","user verification required","user authentication required",
"verify contact information","confirm contact information","update contact information","verify email address","confirm email address","update email address","verify phone number","confirm phone number","update phone number","email verification required","phone verification required","contact verification required","email confirmation required","phone confirmation required","contact information required",
"new device detected","new device login","new device sign in","new device access","new browser detected","new location detected","new location login","new location sign in","new ip address detected","new ip detected","unknown device detected","unknown location detected","unknown browser detected","unknown session detected","unfamiliar device detected",
"ip address changed","login location changed","account accessed from new location","account accessed from unknown location","account accessed from unfamiliar location","account accessed from new device","account accessed from unknown device","account accessed from unfamiliar device","recent account access","recent suspicious access","recent unauthorized access","recent security event","security event detected","security event requires verification","security event requires confirmation",
"transaction verification required","transaction confirmation required","transaction authentication required","payment verification required","payment confirmation required","payment authentication required","transfer verification required","transfer confirmation required","transfer authentication required","bank verification required","bank account verification","bank account authentication","bank security verification","card verification required","card authentication required",
"identity document required","identity document verification","identity document confirmation","document verification required","document authentication required","upload identification","upload your identification","upload id","upload your id","submit identification","submit your identification","submit id","submit your id","identity document required","proof of identity required",
"verify ownership","confirm ownership","account ownership verification","account ownership confirmation","verify account ownership","confirm account ownership","prove account ownership","ownership verification required","ownership confirmation required","account holder verification","account holder confirmation","customer verification","customer identity verification","customer authentication","customer account verification",
"security breach detected","security incident detected","potential breach detected","possible breach detected","account breach detected","account compromise detected","account security compromised","account may be compromised","account appears compromised","suspicious access detected","unauthorized access detected","unauthorized activity detected","security threat detected","security risk detected","security issue detected",
"protect your account now","secure your account now","verify your account now","confirm your account now","update your account now","restore your account now","unlock your account now","reactivate your account now","recover your account now","reset your password now","verify your identity now","confirm your identity now","complete verification now","complete authentication now","complete security check now",
"final verification","final account verification","final security verification","final identity verification","final confirmation","final authentication","last verification","last confirmation","last security check","account verification deadline","identity verification deadline","security verification deadline","verification deadline","authentication deadline","confirmation deadline",
"verification expires","verification will expire","verification has expired","verification expired","verification link expires","verification link expired","verification request expires","confirmation expires","authentication expires","security verification expires","verification must be completed","verification must be completed today","verification must be completed immediately","verification must be completed within 24 hours","verification must be completed within 48 hours"
];


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
"expires today","expires soon","offer available","offer available now","offer valid today","offer valid this week","offer valid until","promotion ends","promotion ends soon","promotion expires","promotion expires soon","deal ends","deal ends soon","sale ends","sale ends soon","discount ends","discount expires","coupon expires","voucher expires","reward expires",
"huge savings","big savings","massive savings","save big","save money","save more","save up to","save upto","up to 50 percent off","up to 70 percent off","up to 80 percent off","up to 90 percent off","50 percent off","60 percent off","70 percent off","80 percent off","90 percent off","half price","half off","price drop",
"best price","lowest price","cheap price","special price","exclusive price","discounted price","reduced price","sale price","special pricing","member price","member pricing","customer pricing","early bird price","introductory price","special rate","lowest rate","best rate","exclusive rate","reduced rate","limited price",
"promo code","promotional code","promotion code","coupon code","discount code","offer code","voucher code","gift code","reward code","cashback code","referral code","special code","exclusive code","member code","customer code","redeem code","promo voucher","discount voucher","gift voucher","shopping voucher",
"voucher","gift voucher","shopping voucher","discount voucher","cashback","cash back","instant cashback","extra cashback","cashback offer","cashback reward","cashback bonus","cashback deal","cashback available","earn cashback","get cashback","receive cashback","bonus","welcome bonus","instant bonus","special bonus","member bonus","customer bonus","signup bonus","sign up bonus","referral bonus","deposit bonus",
"reward points","bonus points","loyalty points","membership points","customer points","bonus reward","reward bonus","reward offer","loyalty reward","member reward","customer reward","redeem points","redeem rewards","earn points","earn rewards","double points","triple points","extra points","bonus points available","points promotion",
"free money","easy money","make money","make money fast","make money online","earn money","earn money online","earn extra income","extra income","passive income","online income","easy income","quick income","fast income","additional income","monthly income","weekly income","daily income","instant income","guaranteed income",
"get rich","get rich quick","get rich fast","wealth opportunity","money making opportunity","money making program","income opportunity","business opportunity","online opportunity","work opportunity","career opportunity","investment opportunity","profit opportunity","earning opportunity","financial opportunity","exclusive opportunity","limited opportunity","special opportunity","business offer","income program",
"work from home","work from home opportunity","home based job","home based work","online job","online work","remote job opportunity","remote work opportunity","part time job","part time work","full time opportunity","easy job","easy work","easy income","flexible job","flexible work","earn from home","earn while you sleep","work online","job opportunity",
"guaranteed income","guaranteed returns","guaranteed profit","guaranteed earnings","guaranteed money","guaranteed results","guaranteed approval","guaranteed acceptance","guaranteed reward","guaranteed prize","risk free","risk-free","no risk","zero risk","low risk","no investment","zero investment","no upfront cost","no fees","no experience required",
"investment opportunity","investment offer","investment plan","investment program","investment deal","investment bonus","investment reward","high returns","high return","guaranteed returns","guaranteed return","quick returns","fast returns","instant returns","passive returns","profit guaranteed","profit opportunity","financial opportunity","wealth opportunity","earn high returns",
"cheap price","lowest price","best price","special price","exclusive price","discounted price","reduced price","low price","low cost","special rate","lowest rate","best rate","affordable price","budget price","clearance price","wholesale price","member price","early bird price","introductory price","promotional price",
"free shipping","free delivery","free express shipping","free next day delivery","free standard delivery","free shipping offer","free delivery offer","free shipping today","free delivery today","complimentary shipping","complimentary delivery","shipping discount","delivery discount","reduced shipping","reduced delivery","shipping promotion","delivery promotion","shipping offer","delivery offer","shipping bonus",
"free membership","free upgrade","upgrade now","upgrade today","premium upgrade","free premium","premium access","exclusive access","special access","early access","priority access","vip access","vip membership","premium membership","exclusive membership","special membership","free subscription","free trial","trial offer","subscription offer",
"click here","click now","click today","click to claim","click to redeem","click to win","click for offer","click for discount","click for reward","click for prize","click to register","click to subscribe","click to shop","click to apply","click to learn more","learn more","find out more","discover more","see offer","view offer",
"one time offer","one-time offer","one time deal","one-time deal","one time discount","one-time discount","one time promotion","one-time promotion","today only","available today","valid today","offer today","special today","deal today","discount today","promotion today","exclusive today","limited today","act today",
"giveaway","free giveaway","exclusive giveaway","special giveaway","cash giveaway","prize giveaway","product giveaway","gift giveaway","contest","free contest","prize contest","special contest","exclusive contest","winner announcement","prize draw","cash draw","reward draw","giveaway winner","contest winner","draw winner",
"survey reward","survey prize","survey bonus","survey gift","survey cashback","complete survey","take survey","participate in survey","customer survey","customer reward survey","feedback reward","feedback bonus","feedback gift","feedback prize","review reward","review bonus","review gift","review offer","feedback offer","customer feedback reward",
"refer a friend","refer friends","referral offer","referral reward","referral bonus","referral program","invite friends","invite a friend","invite and earn","refer and earn","share and earn","earn rewards","earn bonus","earn cashback","earn points","member referral","customer referral","friend referral","referral discount","referral coupon"
];

const urgencyKeywords=[
"urgent","urgently","immediately","immediate action","act now","act immediately","take action now","action required","action needed","action requested","action must be taken","response required","response needed","reply required","reply immediately","respond immediately","respond now","respond today","respond as soon as possible","respond without delay",
"final warning","final notice","final alert","final reminder","last warning","last notice","last reminder","last chance","final opportunity","last opportunity","urgent notice","urgent alert","urgent request","urgent action","urgent response","urgent verification","urgent confirmation","urgent attention",
"expires today","expire today","expires soon","expiring soon","expiration today","deadline today","due today","due immediately","deadline approaching","deadline is approaching","approaching deadline","short deadline","limited time","limited timeframe","limited window","limited period","time sensitive","time-sensitive","time critical","time-critical",
"immediate response","immediate attention","immediate verification","immediate confirmation","immediate action required","immediate attention required","immediate response required","immediate verification required","immediate confirmation required","immediate payment required","immediate update required","immediate login required","immediate account action",
"within 24 hours","within 48 hours","within 12 hours","within 6 hours","within 2 hours","within 1 hour","within one hour","within two hours","within six hours","within twelve hours","within twenty four hours","within twenty-four hours","within forty eight hours","within forty-eight hours","before 24 hours","before 48 hours",
"do not delay","do not wait","don't delay","don't wait","without delay","without further delay","without waiting","do this now","do it now","complete this now","complete immediately","finish immediately","verify immediately","confirm immediately","update immediately","login immediately","sign in immediately","respond without delay","reply without delay","contact us immediately",
"as soon as possible","asap","at once","right away","straight away","without hesitation","without further notice","without further action","before it is too late","before it's too late","before the deadline","before deadline","before expiration","before expiry","before your access expires","before access expires","before account closure",
"account will expire","account expires soon","account expires today","account access expires","access will expire","access expires soon","access expires today","service will expire","service expires soon","subscription expires today","subscription expires soon","payment deadline","payment due today","payment due immediately","payment required today","payment required immediately",
"account suspension","account suspended","account will be suspended","account may be suspended","account closure","account will be closed","account may be closed","account termination","account will be terminated","account may be terminated","access restriction","access restricted","access will be restricted","access may be restricted","service suspension","service will be suspended","service may be suspended","service termination",
"security alert","security warning","security notice","security threat","critical alert","critical warning","critical notice","important security alert","important warning","important notice","high priority","high priority alert","priority alert","priority notice","critical action required","critical response required","critical verification required","critical update required","critical security update",
"failure to respond","failure to act","failure to verify","failure to confirm","failure to update","failure to complete","failure to respond will result","failure to act will result","failure to verify will result","failure to confirm will result","failure to update will result","failure to comply","non-compliance","if you do not respond","if you don't respond","if you fail to respond","if you fail to act","if you fail to verify","if you fail to confirm","if you fail to update",
"your account will be locked","your account may be locked","account will be locked","account may be locked","your account will be suspended","your account may be suspended","your account will be closed","your account may be closed","your access will be revoked","your access may be revoked","your access will be blocked","your access may be blocked","your service will be interrupted","your service may be interrupted","your account will be disabled","your account may be disabled",
"avoid suspension","avoid account closure","avoid account termination","prevent suspension","prevent account closure","prevent access loss","restore access immediately","restore account access","regain access immediately","unlock your account immediately","reactivate your account immediately","secure your account immediately","protect your account immediately","verify before suspension","verify before closure","confirm before suspension","confirm before closure","update before suspension","update before closure",
"deadline","urgent deadline","strict deadline","hard deadline","submission deadline","verification deadline","confirmation deadline","payment deadline","security deadline","account deadline","response deadline","deadline notification","deadline reminder","deadline warning","deadline notice","deadline approaching","deadline passed","deadline has passed","missed deadline","overdue",
"overdue action","overdue verification","overdue confirmation","overdue payment","overdue response","overdue update","overdue account review","past due","past due payment","past due verification","past due confirmation","immediate payment","payment immediately","pay immediately","payment required","payment due","payment overdue","payment must be completed","payment must be made","payment must be confirmed",
"urgent payment","urgent payment request","urgent transfer","urgent transaction","urgent account review","urgent identity verification","urgent security verification","urgent password reset","urgent login","urgent sign in","urgent confirmation","urgent document verification","urgent document submission","urgent information request","urgent compliance request","urgent security action","urgent account update","urgent profile update","urgent billing update",
"today only","available today only","valid today only","offer ends today","offer expires today","promotion ends today","promotion expires today","access ends today","access expires today","verification ends today","verification expires today","confirmation ends today","confirmation expires today","registration closes today","registration ends today","response closes today","request expires today","link expires today","link will expire today","link expires soon",
"one day remaining","few hours remaining","hours remaining","minutes remaining","only hours left","only minutes left","limited hours","limited minutes","countdown","countdown ending","closing soon","ending soon","ends soon","expires in hours","expires in minutes","expiration approaching","expiration imminent","expiry approaching","expiry imminent","deadline imminent",
"immediate compliance","compliance required","compliance deadline","regulatory deadline","policy deadline","security compliance required","mandatory action","mandatory response","mandatory verification","mandatory confirmation","mandatory update","mandatory payment","required immediately","required today","required before deadline","required before expiration","required within 24 hours","required within 48 hours","required without delay"
];

const credentialKeywords=[
"login credentials","account credentials","user credentials","user login","login details","account login details","login information","account information","login data","account login","login authentication","account authentication","user authentication","login verification","account verification",
"username","user name","user id","userid","login id","login username","account username","account user id","user identification","login identity","account identity","member id","customer id","client id","employee id",
"username and password","username/password","user id and password","user id/password","login id and password","login id/password","account id and password","account username and password","user name and password","user name/password","email and password","email/password","login name and password","login credentials required","credentials required",
"enter your username","enter username","enter your user id","enter user id","enter your login id","enter login id","enter your account id","enter account id","enter your login name","enter login name","provide your username","provide username","provide your user id","provide user id","provide your login id","provide login id",
"password","account password","login password","user password","current password","old password","new password","temporary password","one time password","one-time password","one time passcode","one-time passcode","temporary login password","temporary access password","account login password","user login password","online password","portal password","service password","member password",
"enter your password","enter password","enter the password","enter your account password","enter account password","enter your login password","enter login password","provide your password","provide password","provide the password","provide your account password","submit your password","submit password","submit the password","submit your account password","confirm your password","confirm password","confirm the password","confirm your account password","verify your password",
"re-enter your password","reenter your password","re enter your password","type your password","type password","input your password","input password","update your password","change your password","reset your password","recover your password","restore your password","validate your password","authenticate your password","password verification","password confirmation","password authentication","password validation","password check","password required",
"security code","security verification code","security number","security token","security key","security credential","security credentials","security verification","security authentication","security confirmation","security validation","security check","security passcode","security pass phrase","security passphrase","security identifier","security response","security answer","security question","security challenge",
"verification code","verification number","verification token","verification key","verification passcode","verification password","verification phrase","verification identifier","verification response","verification value","verification credential","verification credentials","verification details","verification information","verification data","account verification code","account verification number","account verification token","account verification key","account verification passcode",
"authentication code","authentication number","authentication token","authentication key","authentication passcode","authentication password","authentication phrase","authentication identifier","authentication response","authentication value","authentication credential","authentication credentials","authentication details","authentication information","authentication data","account authentication code","account authentication token","account authentication key","login authentication code","login authentication token",
"auth code","auth token","auth key","auth passcode","auth password","auth credentials","auth credential","auth verification","authenticator code","authenticator token","authenticator key","authenticator password","authenticator verification","authenticator passcode","authenticator credentials","authentication passcode","authentication challenge","authentication response","authentication request","authentication confirmation",
"confirmation code","confirmation number","confirmation token","confirmation key","confirmation passcode","confirmation password","confirmation credential","confirmation credentials","confirmation details","confirmation information","confirmation data","account confirmation code","account confirmation number","account confirmation token","account confirmation key","account confirmation passcode","account confirmation password","login confirmation code","login confirmation token","login confirmation request",
"access code","access token","access key","access passcode","access password","access credential","access credentials","access verification","access authentication","access confirmation","access details","access information","access data","account access code","account access token","account access key","account access password","account access credentials","login access code","login access token",
"one time password","one-time password","one time passcode","one-time passcode","one time code","one-time code","one time verification","one-time verification","one time authentication","one-time authentication","one time token","one-time token","single use password","single-use password","single use passcode","single-use passcode","temporary verification code","temporary authentication code","temporary access code","temporary security code",
"otp","otp code","otp number","otp token","otp password","otp passcode","otp verification","otp authentication","otp confirmation","otp security code","otp security token","otp credential","otp credentials","otp request","otp required","otp verification required","otp authentication required","otp confirmation required","otp validation","otp check",
"enter otp","enter the otp","enter your otp","enter otp code","enter the otp code","enter your otp code","provide otp","provide the otp","provide your otp","provide otp code","provide the otp code","submit otp","submit the otp","submit your otp","submit otp code","confirm otp","confirm the otp","confirm your otp","verify otp","verify the otp",
"send otp","send the otp","send your otp","share otp","share the otp","share your otp","forward otp","forward the otp","reply with otp","reply with the otp","return otp","return the otp","provide verification code","provide the verification code","send verification code","send the verification code","share verification code","share the verification code","submit verification code","submit the verification code",
"pin","pin code","security pin","account pin","login pin","verification pin","authentication pin","access pin","transaction pin","banking pin","card pin","atm pin","online banking pin","mobile banking pin","payment pin","payment security pin","account security pin","user pin","customer pin","member pin",
"enter pin","enter the pin","enter your pin","enter pin code","enter your pin code","provide pin","provide the pin","provide your pin","submit pin","submit the pin","submit your pin","confirm pin","confirm the pin","confirm your pin","verify pin","verify the pin","verify your pin","send pin","share pin","provide pin code",
"credit card number","credit card details","credit card information","credit card data","credit card credentials","credit card security","credit card verification","credit card authentication","credit card confirmation","credit card payment details","credit card billing details","credit card account details","credit card identification","credit card validation","credit card number required","credit card details required","credit card information required","credit card verification required","credit card authentication required","credit card confirmation required",
"debit card number","debit card details","debit card information","debit card data","debit card credentials","debit card security","debit card verification","debit card authentication","debit card confirmation","debit card payment details","debit card billing details","debit card account details","debit card identification","debit card validation","debit card number required","debit card details required","debit card information required","debit card verification required","debit card authentication required","debit card confirmation required",
"card number","card details","card information","card data","card credentials","card security","card verification","card authentication","card confirmation","card payment details","card billing details","card account details","card identification","card validation","card number required","card details required","card information required","card verification required","card authentication required","card confirmation required",
"cardholder name","card holder name","cardholder information","card holder information","cardholder details","card holder details","cardholder data","card holder data","card expiry","card expiration","card expiration date","card expiry date","expiry date","expiration date","expiration month","expiration year","expiry month","expiry year","valid through","valid thru",
"cvv","cvv code","cvv number","cvv2","cvv2 code","cvv2 number","cvc","cvc code","cvc number","cvc2","cvc2 code","cvc2 number","security number","card security code","card security number","card verification code","card verification number","card authentication code","card authentication number","three digit code",
"3 digit code","three-digit code","four digit code","four-digit code","card pin","payment pin","payment verification code","payment security code","payment authentication code","payment confirmation code","transaction verification code","transaction security code","transaction authentication code","transaction confirmation code","payment credentials","payment information","payment details","payment card details","payment card information","payment card number",
"bank account details","bank account information","bank account data","bank account number","banking details","banking information","banking data","banking credentials","banking credential","bank login","bank login details","bank username","bank password","banking username","banking password","account number","account details","account information","account data","account verification",
"routing number","routing code","routing details","routing information","sort code","sort code details","sort code information","ifsc code","ifsc number","ifsc details","swift code","swift number","swift details","swift information","iban","iban number","iban details","iban information","bank identifier","bank identification",
"online banking details","online banking information","online banking credentials","online banking login","online banking username","online banking password","online banking verification","online banking authentication","online banking security code","online banking access code","mobile banking details","mobile banking information","mobile banking credentials","mobile banking login","mobile banking username","mobile banking password","mobile banking verification","mobile banking authentication","mobile banking security code","mobile banking access code",
"transaction password","transaction pin","transaction code","transaction token","transaction verification","transaction authentication","transaction confirmation","transaction security code","transaction authorization code","transaction authorization","payment password","payment passcode","payment token","payment credential","payment credentials","payment verification","payment authentication","payment confirmation","payment authorization","payment security",
"social security number","social security details","social security information","social security data","social security id","tax identification number","tax identification","tax id","tax number","tax details","tax information","tax credentials","national id","national identification number","national identification","national id number","government id","government id number","government identification","government identification number",
"passport number","passport details","passport information","passport data","passport id","passport identification","passport verification","passport authentication","driving license number","driving licence number","driver license number","driver licence number","driver identification","license number","licence number","identity number","identity details","identity information","identity data","identity credentials",
"personal identification","personal identification number","personal id","personal id number","personal details","personal information","personal data","personal credentials","identity verification","identity confirmation","identity authentication","identity validation","identity check","identity credentials","identity document","identity document number","id verification","id confirmation","id authentication","id validation",
"secret question","secret answer","security question","security answer","recovery question","recovery answer","account recovery question","account recovery answer","password recovery question","password recovery answer","login recovery question","login recovery answer","security challenge question","security challenge answer","account security question","account security answer","verification question","verification answer","authentication question","authentication answer",
"recovery code","recovery codes","account recovery code","account recovery codes","password recovery code","password recovery codes","login recovery code","login recovery codes","backup code","backup codes","backup verification code","backup authentication code","backup security code","recovery token","recovery tokens","recovery key","recovery keys","account recovery key","password recovery key","login recovery key",
"private key","private keys","secret key","secret keys","access key","access keys","security key","security keys","encryption key","encryption keys","authentication key","authentication keys","account key","account security key","recovery key","backup key","master key","master password","secret credential","secret credentials",
"send your credentials","send credentials","share your credentials","share credentials","submit your credentials","submit credentials","provide your credentials","provide credentials","enter your credentials","enter credentials","verify your credentials","verify credentials","confirm your credentials","confirm credentials","update your credentials","update credentials","validate your credentials","validate credentials","authenticate your credentials","authenticate credentials",
"send your password","send password","share your password","share password","provide your password","provide password","submit your password","submit password","enter your password","enter password","verify your password","verify password","confirm your password","confirm password","update your password","update password","validate your password","validate password","authenticate your password","authenticate password",
"send your pin","send pin","share your pin","share pin","provide your pin","provide pin","submit your pin","submit pin","enter your pin","enter pin","verify your pin","verify pin","confirm your pin","confirm pin","send your card details","send card details","share your card details","share card details","provide your card details","provide card details",
"submit card details","submit your card details","enter card details","enter your card details","verify card details","verify your card details","confirm card details","confirm your card details","send bank details","send your bank details","share bank details","share your bank details","provide bank details","provide your bank details","submit bank details","submit your bank details","enter bank details","enter your bank details","verify bank details","verify your bank details",
"send verification code","send the verification code","share verification code","share the verification code","provide verification code","provide the verification code","submit verification code","submit the verification code","enter verification code","enter the verification code","verify verification code","confirm verification code","send security code","send the security code","share security code","share the security code","provide security code","provide the security code","submit security code","submit the security code",
"verify your account","confirm your account","validate your account","authenticate your account","verify account","confirm account","validate account","authenticate account","verify your identity","confirm your identity","validate your identity","authenticate your identity","verify identity","confirm identity","validate identity","authenticate identity","complete account verification","complete identity verification","complete security verification",
"complete authentication","complete verification","account verification required","identity verification required","security verification required","authentication required","additional verification required","additional authentication required","additional security verification","account authentication required","identity authentication required","security authentication required","verification required","validation required","authentication needed","verification needed","identity check required","security check required","account security check","account validation required"
];

const brandVariants=[
"paypa1","pay-pal","paypaI","paypa1-security","paypal-security","paypal-support","paypal-login","paypal-verify","secure-paypal","paypal-account","paypal-alert","paypal-service","paypal-confirm","paypal-protection",
"micros0ft","micro-soft","micros0ft-security","microsoft-security","microsoft-support","microsoft-login","microsoft-verify","secure-microsoft","microsoft-account","microsoft-alert","microsoft-office","office365-security","office365-login","microsoft365-security","microsoft365-login",
"amaz0n","amaz-on","amaz0n-security","amazon-security","amazon-support","amazon-login","amazon-verify","secure-amazon","amazon-account","amazon-alert","amazon-prime","amazon-billing","amazon-payment","amazon-order","amazon-delivery",
"g00gle","g0ogle","goog1e","google-security","google-support","google-login","google-verify","secure-google","google-account","google-alert","google-drive","google-cloud","gmail-security","gmail-support","gmail-login","gmail-verify",
"faceb00k","faceb0ok","facebok","facebook-security","facebook-support","facebook-login","facebook-verify","secure-facebook","facebook-account","facebook-alert","facebook-business","facebook-protection",
"app1e","appIe","appl3","apple-security","apple-support","apple-login","apple-verify","secure-apple","apple-account","apple-alert","icloud-security","icloud-support","icloud-login","icloud-verify",
"netfl1x","netf1ix","netflix-security","netflix-support","netflix-login","netflix-verify","secure-netflix","netflix-account","netflix-alert","netflix-billing","netflix-payment","netflix-renewal",
"linkedln","link3din","linkedin-security","linkedin-support","linkedin-login","linkedin-verify","secure-linkedin","linkedin-account","linkedin-alert","linkedin-jobs",
"dell-support","dell-security","dell-login","dell-verify","secure-dell","dell-account","dell-alert","dell-service","dell-technologies",
"ad0be","adobe-security","adobe-support","adobe-login","adobe-verify","secure-adobe","adobe-account",
"dropb0x","dropbox-security","dropbox-support","dropbox-login","dropbox-verify","secure-dropbox","dropbox-account",
"0ne-drive","onedrive-security","onedrive-support","onedrive-login","onedrive-verify","secure-onedrive","onedrive-account",
"0utlook","outlook-security","outlook-support","outlook-login","outlook-verify","secure-outlook","outlook-account",
"y0utube","youtube-security","youtube-support","youtube-login","youtube-verify","secure-youtube","youtube-account",
"instagr4m","instagram-security","instagram-support","instagram-login","instagram-verify","secure-instagram","instagram-account",
"tw1tter","twitter-security","twitter-support","twitter-login","twitter-verify","secure-twitter","twitter-account",
"disc0rd","discord-security","discord-support","discord-login","discord-verify","secure-discord","discord-account",
"ste4m","steam-security","steam-support","steam-login","steam-verify","secure-steam","steam-account",
"sp0tify","spotify-security","spotify-support","spotify-login","spotify-verify","secure-spotify","spotify-account",
"chase-security","chase-support","chase-login","chase-verify","secure-chase","chase-account","chase-alert",
"wellsfargo-security","wellsfargo-support","wellsfargo-login","wellsfargo-verify","secure-wellsfargo","wellsfargo-account",
"bankofamerica-security","bankofamerica-support","bankofamerica-login","bankofamerica-verify","secure-bankofamerica","bankofamerica-account",
"citibank-security","citibank-support","citibank-login","citibank-verify","secure-citibank","citibank-account",
"hsbc-security","hsbc-support","hsbc-login","hsbc-verify","secure-hsbc","hsbc-account",
"barclays-security","barclays-support","barclays-login","barclays-verify","secure-barclays","barclays-account",
"paypal","microsoft","amazon","google","facebook","apple","netflix","linkedin"
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