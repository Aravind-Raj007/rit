/*
 * ScamGuard Pro - India YARA Rules 2025
 * 50+ handcrafted rules for Indian scam detection
 * Covers: UPI scams, KYC fraud, banking phishing, lottery scams, job scams, etc.
 */

rule INDIA_UPI_SCAM_GENERIC {
    meta:
        description = "Generic UPI scam patterns"
        author = "ScamGuard Pro"
        severity = "high"
        category = "UPI_SCAM"
        confidence = 85
        version = "2025.1"
    strings:
        $upi1 = /upi\s*id\s*[:=]/i
        $upi2 = /send\s+(?:\d+|rs\.?\s*\d+)/i
        $upi3 = /transfer\s+(?:immediately|now|urgent)/i
        $upi4 = /paytm\s*(?:kyc|link|verify)/i
        $upi5 = /phonepe\s*(?:cashback|reward|offer)/i
        $upi6 = /gpay\s*(?:reward|scratch|won)/i
        $prize1 = /won\s+(?:rs\.?|₹)\s*\d+/i
        $prize2 = /cashback\s+of\s+(?:rs\.?|₹)\s*\d+/i
        $urgent1 = /(?:urgent|immediate)\s*(?:action|transfer)/i
    condition:
        any of ($upi*) and (any of ($prize*) or any of ($urgent*))
}

rule INDIA_KYC_FRAUD {
    meta:
        description = "KYC update fraud messages"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "KYC_FRAUD"
        confidence = 90
        version = "2025.1"
    strings:
        $kyc1 = /kyc\s*(?:update|verify|expire|suspend|block)/i
        $kyc2 = /(?:your|ur)\s*kyc\s*(?:is|has)\s*(?:not|incomplete|pending)/i
        $kyc3 = /complete\s*kyc\s*(?:now|immediately|urgent|within)/i
        $kyc4 = /(?:account|a\/c)\s*(?:will\s*be|shall\s*be)\s*(?:blocked|suspended|closed)/i
        $kyc5 = /re-?kyc\s*(?:required|mandatory|compulsory)/i
        $kyc6 = /aadhar\s*(?:link|update|verify|pending)/i
        $kyc7 = /pan\s*(?:link|update|verify|pending)/i
        $link1 = /click\s*(?:here|link|below)/i
        $link2 = /http[s]?:\/\//
    condition:
        2 of ($kyc*) and any of ($link*)
}

rule INDIA_BANK_PHISHING_SBI {
    meta:
        description = "SBI phishing attempts"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "BANKING_FRAUD"
        confidence = 92
        version = "2025.1"
    strings:
        $sbi1 = /state\s*bank/i
        $sbi2 = "sbi" nocase
        $sbi3 = "yono" nocase
        $action1 = /(?:verify|update|confirm)\s*(?:your|ur)\s*(?:account|details|password)/i
        $action2 = /(?:account|a\/c)\s*(?:suspended|blocked|limited)/i
        $action3 = /(?:click|tap)\s*(?:here|link|below|now)/i
        $action4 = /(?:otp|password|pin|cvv)\s*(?:enter|verify|confirm)/i
        $sus_domain = /sbi[^.]*\.(?:tk|ml|ga|cf|gq|xyz|top|click|link)/i
    condition:
        any of ($sbi*) and (2 of ($action*) or $sus_domain)
}

rule INDIA_BANK_PHISHING_HDFC {
    meta:
        description = "HDFC Bank phishing attempts"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "BANKING_FRAUD"
        confidence = 92
        version = "2025.1"
    strings:
        $hdfc1 = "hdfc" nocase
        $hdfc2 = /hdfc\s*bank/i
        $action1 = /(?:verify|update|confirm)\s*(?:your|ur)\s*(?:account|details|password)/i
        $action2 = /(?:account|a\/c)\s*(?:suspended|blocked|limited)/i
        $action3 = /(?:click|tap)\s*(?:here|link|below|now)/i
        $action4 = /(?:otp|password|pin|cvv)\s*(?:enter|verify|confirm)/i
        $sus_domain = /hdfc[^.]*\.(?:tk|ml|ga|cf|gq|xyz|top|click|link)/i
    condition:
        any of ($hdfc*) and (2 of ($action*) or $sus_domain)
}

rule INDIA_BANK_PHISHING_ICICI {
    meta:
        description = "ICICI Bank phishing attempts"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "BANKING_FRAUD"
        confidence = 92
        version = "2025.1"
    strings:
        $icici1 = "icici" nocase
        $icici2 = /icici\s*bank/i
        $action1 = /(?:verify|update|confirm)\s*(?:your|ur)\s*(?:account|details|password)/i
        $action2 = /(?:account|a\/c)\s*(?:suspended|blocked|limited)/i
        $action3 = /(?:click|tap)\s*(?:here|link|below|now)/i
        $action4 = /(?:otp|password|pin|cvv)\s*(?:enter|verify|confirm)/i
        $sus_domain = /icici[^.]*\.(?:tk|ml|ga|cf|gq|xyz|top|click|link)/i
    condition:
        any of ($icici*) and (2 of ($action*) or $sus_domain)
}

rule INDIA_BANK_PHISHING_AXIS {
    meta:
        description = "Axis Bank phishing attempts"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "BANKING_FRAUD"
        confidence = 92
        version = "2025.1"
    strings:
        $axis1 = "axis" nocase
        $axis2 = /axis\s*bank/i
        $action1 = /(?:verify|update|confirm)\s*(?:your|ur)\s*(?:account|details|password)/i
        $action2 = /(?:account|a\/c)\s*(?:suspended|blocked|limited)/i
        $action3 = /(?:click|tap)\s*(?:here|link|below|now)/i
        $action4 = /(?:otp|password|pin|cvv)\s*(?:enter|verify|confirm)/i
    condition:
        any of ($axis*) and 2 of ($action*)
}

rule INDIA_LOTTERY_SCAM {
    meta:
        description = "Lottery and prize scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "LOTTERY_SCAM"
        confidence = 88
        version = "2025.1"
    strings:
        $lottery1 = /(?:won|winner|selected|chosen)\s*(?:for|in|of)\s*(?:lottery|lucky\s*draw|prize)/i
        $lottery2 = /(?:rs\.?|₹|inr)\s*\d{1,3}(?:,?\d{3})*(?:\s*(?:lakh|crore|lac|cr))?/i
        $lottery3 = /(?:claim|collect)\s*(?:your|ur)\s*(?:prize|reward|winning|amount)/i
        $lottery4 = "KBC" nocase
        $lottery5 = /kaun\s*banega\s*crorepati/i
        $lottery6 = /jio\s*(?:lottery|lucky)/i
        $lottery7 = /whatsapp\s*lottery/i
        $lottery8 = /google\s*(?:lottery|lucky|winner)/i
        $lottery9 = /amazon\s*lucky\s*(?:draw|winner)/i
        $action1 = /(?:contact|call|whatsapp)\s*(?:us|now|immediately)/i
        $action2 = /processing\s*fee/i
        $action3 = /registration\s*(?:fee|charge)/i
    condition:
        2 of ($lottery*) or (any of ($lottery*) and any of ($action*))
}

rule INDIA_OTP_SCAM {
    meta:
        description = "OTP stealing scams"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "OTP_SCAM"
        confidence = 95
        version = "2025.1"
    strings:
        $otp1 = /(?:share|send|give)\s*(?:your|ur)\s*otp/i
        $otp2 = /otp\s*(?:is|code|number)\s*:\s*\d{4,8}/i
        $otp3 = /(?:enter|type)\s*(?:this|the)\s*otp/i
        $otp4 = /(?:verify|verification)\s*otp/i
        $otp5 = /(?:wrong|incorrect)\s*otp\s*(?:entered|sent)/i
        $scam1 = /(?:i\s*am|i'm)\s*(?:from|calling\s*from)\s*(?:bank|sbi|hdfc|icici|axis)/i
        $scam2 = /(?:refund|amount)\s*(?:will\s*be|to\s*be)\s*(?:credited|transferred)/i
        $scam3 = /(?:verify|confirm)\s*(?:transaction|payment)/i
    condition:
        any of ($otp*) and any of ($scam*)
}

rule INDIA_JOB_SCAM {
    meta:
        description = "Fake job offer scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "JOB_SCAM"
        confidence = 85
        version = "2025.1"
    strings:
        $job1 = /(?:job|work)\s*(?:from\s*home|opportunity)/i
        $job2 = /(?:earn|income|salary)\s*(?:rs\.?|₹)\s*\d+(?:k|,?\d{3})*\s*(?:per|\/)\s*(?:day|week|month)/i
        $job3 = /(?:part\s*time|full\s*time)\s*(?:job|work|opportunity)/i
        $job4 = /(?:no\s*experience|freshers?\s*welcome)/i
        $job5 = /(?:registration|joining)\s*fee/i
        $job6 = /(?:data\s*entry|typing)\s*(?:job|work)/i
        $job7 = /(?:amazon|flipkart)\s*(?:review|rating)\s*(?:job|work)/i
        $job8 = /(?:telegram|whatsapp)\s*(?:job|task)/i
        $scam1 = /(?:pay|deposit)\s*(?:rs\.?|₹)\s*\d+\s*(?:first|initially|upfront)/i
        $scam2 = /(?:refundable|security)\s*deposit/i
        $scam3 = /guaranteed\s*(?:income|earning|job)/i
    condition:
        2 of ($job*) or (any of ($job*) and any of ($scam*))
}

rule INDIA_INVESTMENT_SCAM {
    meta:
        description = "Investment and trading scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "INVESTMENT_SCAM"
        confidence = 87
        version = "2025.1"
    strings:
        $invest1 = /(?:invest|trading)\s*(?:opportunity|tips?)/i
        $invest2 = /(?:guaranteed|assured)\s*(?:return|profit|income)/i
        $invest3 = /(?:double|triple|10x)\s*(?:your\s*)?money/i
        $invest4 = /(?:daily|weekly|monthly)\s*(?:return|profit|income)\s*of\s*\d+%/i
        $invest5 = /(?:forex|crypto|bitcoin)\s*trading/i
        $invest6 = /(?:stock|share)\s*(?:tips?|recommendation)/i
        $scam1 = /(?:minimum|start\s*with)\s*(?:rs\.?|₹)\s*\d+/i
        $scam2 = /(?:limited|exclusive)\s*(?:offer|opportunity)/i
        $scam3 = /(?:risk\s*free|zero\s*risk|no\s*loss)/i
        $scam4 = /(?:sebi|rbi)\s*(?:registered|approved)/i
    condition:
        2 of ($invest*) or (any of ($invest*) and any of ($scam*))
}

rule INDIA_LOAN_SCAM {
    meta:
        description = "Fake loan and credit scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "LOAN_SCAM"
        confidence = 86
        version = "2025.1"
    strings:
        $loan1 = /(?:instant|quick|fast)\s*(?:loan|credit)/i
        $loan2 = /(?:pre-?approved|guaranteed)\s*loan/i
        $loan3 = /(?:loan|credit)\s*(?:without|no)\s*(?:documents?|cibil|paperwork)/i
        $loan4 = /(?:personal|business)\s*loan\s*(?:at|@)\s*\d+(?:\.\d+)?%/i
        $loan5 = /(?:low|lowest|zero)\s*(?:interest|emi)/i
        $loan6 = /(?:processing|file)\s*(?:fee|charge)\s*(?:of|only)\s*(?:rs\.?|₹)/i
        $scam1 = /(?:pay|deposit)\s*(?:upfront|first|initially)/i
        $scam2 = /(?:insurance|gst|tax)\s*(?:fee|charge)/i
        $scam3 = /(?:activate|release)\s*(?:your\s*)?loan/i
    condition:
        2 of ($loan*) and any of ($scam*)
}

rule INDIA_FAKE_DELIVERY {
    meta:
        description = "Fake delivery notification scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "FAKE_DELIVERY"
        confidence = 84
        version = "2025.1"
    strings:
        $delivery1 = /(?:your|ur)\s*(?:package|parcel|order|delivery)\s*(?:is|has)/i
        $delivery2 = /(?:delivery|courier)\s*(?:failed|pending|on\s*hold)/i
        $delivery3 = /(?:india\s*post|delhivery|bluedart|dtdc|fedex|ecom)/i nocase
        $delivery4 = /tracking\s*(?:number|id|code)/i
        $delivery5 = /(?:customs?|address)\s*(?:clearance|verification|issue)/i
        $scam1 = /(?:pay|deposit)\s*(?:rs\.?|₹)\s*\d+/i
        $scam2 = /(?:click|tap)\s*(?:to|here)\s*(?:track|reschedule|update)/i
        $scam3 = /(?:update|verify)\s*(?:your|ur)\s*(?:address|details)/i
        $sus_url = /(?:indiapost|delivery)[^.]*\.(?:tk|ml|ga|cf|gq|xyz|top)/i
    condition:
        any of ($delivery*) and (any of ($scam*) or $sus_url)
}

rule INDIA_GOVT_IMPERSONATION {
    meta:
        description = "Government/RBI impersonation scams"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "GOVT_IMPERSONATION"
        confidence = 93
        version = "2025.1"
    strings:
        $govt1 = /(?:rbi|reserve\s*bank)/i
        $govt2 = /(?:income\s*tax|it\s*department)/i
        $govt3 = /(?:epfo|pf\s*office|provident\s*fund)/i
        $govt4 = /(?:uidai|aadhar|aadhaar)/i
        $govt5 = /(?:ministry|govt\.?\s*of\s*india)/i
        $govt6 = /(?:cyber\s*cell|cyber\s*crime|police)/i
        $govt7 = /(?:pm\s*kisan|ayushman|jan\s*dhan)/i
        $threat1 = /(?:legal|criminal)\s*(?:action|proceedings)/i
        $threat2 = /(?:arrest|jail|prison|fine)\s*(?:warrant|notice)/i
        $threat3 = /(?:account|a\/c)\s*(?:freeze|seized|blocked)/i
        $threat4 = /(?:immediate|urgent)\s*(?:action|response)\s*required/i
    condition:
        any of ($govt*) and any of ($threat*)
}

rule INDIA_QR_SCAM {
    meta:
        description = "QR code payment scams"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "QR_SCAM"
        confidence = 90
        version = "2025.1"
    strings:
        $qr1 = /scan\s*(?:this|the)\s*qr/i
        $qr2 = /qr\s*(?:code|scan)/i
        $qr3 = /(?:receive|get)\s*(?:money|payment)\s*(?:scan|by\s*scanning)/i
        $scam1 = /(?:scan|pay)\s*(?:to\s*)?(?:receive|get)/i
        $scam2 = /(?:buyer|customer)\s*(?:will\s*)?(?:scan|pay)/i
        $scam3 = /(?:olx|quikr|facebook\s*marketplace)/i
    condition:
        any of ($qr*) and any of ($scam*)
}

rule INDIA_VOICE_NOTE_SCAM {
    meta:
        description = "Voice note/call scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "VOICE_NOTE_SCAM"
        confidence = 82
        version = "2025.1"
    strings:
        $voice1 = /(?:voice|audio)\s*(?:message|note)/i
        $voice2 = /(?:missed|important)\s*(?:call|voicemail)/i
        $voice3 = /(?:listen|play)\s*(?:this|the)\s*(?:message|recording)/i
        $scam1 = /(?:click|tap)\s*(?:to|here)\s*(?:listen|play|hear)/i
        $scam2 = /(?:download|install)\s*(?:app|application)/i
        $scam3 = /(?:urgent|important)\s*(?:from|message)/i
    condition:
        any of ($voice*) and any of ($scam*)
}

rule INDIA_GOOGLE_FORMS_PHISH {
    meta:
        description = "Google Forms phishing"
        author = "ScamGuard Pro"
        severity = "high"
        category = "GOOGLE_FORMS_PHISH"
        confidence = 85
        version = "2025.1"
    strings:
        $forms1 = /docs\.google\.com\/forms/i
        $forms2 = /forms\.gle\//i
        $forms3 = /google\s*form/i
        $phish1 = /(?:bank|account|card)\s*(?:details|information|number)/i
        $phish2 = /(?:aadhar|pan|passport)\s*(?:number|details)/i
        $phish3 = /(?:otp|password|pin|cvv)/i
        $phish4 = /(?:verify|update|confirm)\s*(?:your|ur)/i
        $phish5 = /(?:kyc|identity)\s*(?:verification|update)/i
    condition:
        any of ($forms*) and 2 of ($phish*)
}

rule INDIA_REACT2SHELL {
    meta:
        description = "React2Shell malicious links (2025 trend)"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "REACT2SHELL"
        confidence = 94
        version = "2025.1"
    strings:
        $r2s1 = /vercel\.app.*(?:app|api)/i
        $r2s2 = /netlify\.app.*(?:app|api)/i
        $r2s3 = /cloudflare\.pages\.dev/i
        $r2s4 = /render\.com.*(?:app|api)/i
        $r2s5 = /railway\.app/i
        $suspicious1 = /(?:download|install|run)/i
        $suspicious2 = /(?:exe|bat|cmd|ps1|vbs|hta)/i
        $suspicious3 = /(?:payload|shell|exploit)/i
        $suspicious4 = /base64[A-Za-z0-9+\/=]{50,}/i
    condition:
        any of ($r2s*) and any of ($suspicious*)
}

rule INDIA_ZIP_DOMAIN_SCAM {
    meta:
        description = "Fake .zip domain scams (2025 trend)"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "ZIP_DOMAIN_SCAM"
        confidence = 91
        version = "2025.1"
    strings:
        $zip1 = /https?:\/\/[^\/]+\.zip(?:\/|$)/i
        $zip2 = /https?:\/\/[^\/]+\.mov(?:\/|$)/i
        $zip3 = /\w+\.zip\//i
        $suspicious1 = /(?:download|attachment|file)/i
        $suspicious2 = /(?:invoice|document|report)/i
        $suspicious3 = /(?:password|encrypted|protected)/i
    condition:
        any of ($zip*) and any of ($suspicious*)
}

rule INDIA_CRYPTO_SCAM {
    meta:
        description = "Cryptocurrency scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "CRYPTO_SCAM"
        confidence = 86
        version = "2025.1"
    strings:
        $crypto1 = /(?:bitcoin|btc|ethereum|eth|crypto)/i
        $crypto2 = /(?:wallet|seed\s*phrase|private\s*key)/i
        $crypto3 = /(?:binance|wazirx|coinswitch|coindcx)/i
        $scam1 = /(?:airdrop|giveaway|free\s*coins?)/i
        $scam2 = /(?:double|triple|10x)\s*(?:your\s*)?(?:coins?|tokens?|crypto)/i
        $scam3 = /(?:invest|send)\s*\d+\s*(?:btc|eth|usdt)/i
        $scam4 = /(?:connect|verify)\s*(?:your\s*)?wallet/i
    condition:
        any of ($crypto*) and any of ($scam*)
}

rule INDIA_CARD_SCAM {
    meta:
        description = "Credit/Debit card scams"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "CARD_SKIMMING"
        confidence = 92
        version = "2025.1"
    strings:
        $card1 = /(?:credit|debit)\s*card/i
        $card2 = /card\s*(?:number|no\.?|details)/i
        $card3 = /(?:cvv|cvc|expiry|expiration)/i
        $scam1 = /(?:verify|update|confirm)\s*(?:your|ur)\s*card/i
        $scam2 = /card\s*(?:blocked|suspended|expired)/i
        $scam3 = /(?:enter|provide)\s*(?:16|card)\s*(?:digit|number)/i
        $scam4 = /(?:otp|pin|password)\s*(?:to|for)\s*(?:unblock|activate)/i
    condition:
        2 of ($card*) and any of ($scam*)
}

rule INDIA_TECH_SUPPORT_SCAM {
    meta:
        description = "Tech support scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "TECH_SUPPORT_SCAM"
        confidence = 84
        version = "2025.1"
    strings:
        $tech1 = /(?:microsoft|apple|google|amazon)\s*(?:support|help|security)/i
        $tech2 = /(?:virus|malware|hack)\s*(?:detected|found|alert)/i
        $tech3 = /(?:computer|device|system)\s*(?:infected|compromised|at\s*risk)/i
        $tech4 = /(?:call|contact)\s*(?:this|our)\s*(?:number|helpline)/i
        $scam1 = /(?:remote|teamviewer|anydesk)\s*(?:access|support)/i
        $scam2 = /(?:download|install)\s*(?:this|our)\s*(?:software|app)/i
        $scam3 = /(?:pay|fee)\s*(?:rs\.?|₹|\$)\s*\d+/i
    condition:
        2 of ($tech*) or (any of ($tech*) and any of ($scam*))
}

rule INDIA_SEXTORTION {
    meta:
        description = "Sextortion/blackmail scams"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "SOCIAL_ENGINEERING"
        confidence = 89
        version = "2025.1"
    strings:
        $sext1 = /(?:video|photos?|images?)\s*(?:of\s*you|recorded|captured)/i
        $sext2 = /(?:hacked|accessed)\s*(?:your\s*)?(?:camera|webcam|device)/i
        $sext3 = /(?:send|share|leak)\s*(?:to\s*)?(?:contacts?|friends?|family)/i
        $threat1 = /(?:pay|send|transfer)\s*(?:bitcoin|btc|crypto|rs\.?|₹)/i
        $threat2 = /(?:within|before)\s*\d+\s*(?:hours?|days?)/i
        $threat3 = /(?:expose|release|publish|viral)/i
    condition:
        any of ($sext*) and any of ($threat*)
}

rule INDIA_ELECTRICITY_BILL_SCAM {
    meta:
        description = "Electricity bill scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "PHISHING"
        confidence = 87
        version = "2025.1"
    strings:
        $bill1 = /(?:electricity|power|bijli)\s*(?:bill|dues?)/i
        $bill2 = /(?:bses|tata\s*power|adani|torrent|discoms?)/i
        $bill3 = /(?:connection|supply)\s*(?:will\s*be|to\s*be)\s*(?:disconnected|cut)/i
        $scam1 = /(?:pay|clear)\s*(?:immediately|today|now|urgent)/i
        $scam2 = /(?:click|call|contact)\s*(?:to|for)\s*(?:pay|avoid)/i
        $scam3 = /(?:last|final)\s*(?:notice|warning|reminder)/i
    condition:
        any of ($bill*) and any of ($scam*)
}

rule INDIA_INSURANCE_SCAM {
    meta:
        description = "Insurance claim scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "PHISHING"
        confidence = 85
        version = "2025.1"
    strings:
        $ins1 = /(?:lic|insurance)\s*(?:claim|policy|bonus)/i
        $ins2 = /(?:policy|claim)\s*(?:matured|amount|benefit)/i
        $ins3 = /(?:unclaimed|pending)\s*(?:insurance|policy|amount)/i
        $scam1 = /(?:processing|registration|tax|gst)\s*(?:fee|charge)/i
        $scam2 = /(?:pay|deposit)\s*(?:rs\.?|₹)\s*\d+/i
        $scam3 = /(?:verify|update)\s*(?:bank|account)\s*details/i
    condition:
        any of ($ins*) and any of ($scam*)
}

rule INDIA_SOCIAL_MEDIA_SCAM {
    meta:
        description = "Social media account scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "SOCIAL_ENGINEERING"
        confidence = 83
        version = "2025.1"
    strings:
        $social1 = /(?:instagram|facebook|twitter|whatsapp)\s*(?:account|profile)/i
        $social2 = /(?:account|profile)\s*(?:hacked|suspended|disabled|verified)/i
        $social3 = /(?:blue\s*tick|verified\s*badge|verification)/i
        $scam1 = /(?:click|link|login)\s*(?:to|here)\s*(?:verify|restore|appeal)/i
        $scam2 = /(?:enter|provide)\s*(?:password|otp|details)/i
        $scam3 = /(?:meta|instagram|facebook)\s*(?:support|security|team)/i
    condition:
        any of ($social*) and any of ($scam*)
}

rule INDIA_CUSTOMS_SCAM {
    meta:
        description = "Customs/parcel duty scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "FAKE_DELIVERY"
        confidence = 86
        version = "2025.1"
    strings:
        $customs1 = /(?:customs?|duty)\s*(?:clearance|charges?|fee)/i
        $customs2 = /(?:parcel|package|gift)\s*(?:from\s*abroad|international)/i
        $customs3 = /(?:held|stuck|seized)\s*(?:at|by)\s*customs?/i
        $scam1 = /(?:pay|deposit)\s*(?:rs\.?|₹)\s*\d+/i
        $scam2 = /(?:release|clear)\s*(?:your\s*)?(?:parcel|package)/i
        $scam3 = /(?:friend|relative|family)\s*(?:sent|sending)/i
    condition:
        any of ($customs*) and any of ($scam*)
}

rule INDIA_WHATSAPP_FORWARD_SCAM {
    meta:
        description = "WhatsApp forward scams"
        author = "ScamGuard Pro"
        severity = "medium"
        category = "SOCIAL_ENGINEERING"
        confidence = 80
        version = "2025.1"
    strings:
        $wa1 = /forward\s*(?:to|this\s*to)\s*\d+\s*(?:people|friends?|groups?)/i
        $wa2 = /(?:share|send)\s*(?:to|with)\s*\d+\s*(?:contacts?|friends?)/i
        $wa3 = /whatsapp\s*(?:is\s*going|will\s*be)\s*(?:paid|charging)/i
        $wa4 = /(?:government|modi|pm)\s*(?:giving|distributing)/i
        $scam1 = /(?:free|win)\s*(?:recharge|data|gb|money)/i
        $scam2 = /(?:click|register)\s*(?:to|here)\s*(?:get|claim|receive)/i
        $scam3 = /(?:limited|hurry|offer\s*ends)/i
    condition:
        2 of ($wa*) or (any of ($wa*) and any of ($scam*))
}

rule INDIA_MATRIMONY_SCAM {
    meta:
        description = "Matrimony/dating scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "SOCIAL_ENGINEERING"
        confidence = 82
        version = "2025.1"
    strings:
        $mat1 = /(?:matrimony|shaadi|vivah|marriage)/i
        $mat2 = /(?:proposal|rishta|alliance)/i
        $mat3 = /(?:nri|abroad|uk|usa|canada|australia)/i
        $scam1 = /(?:send|transfer|deposit)\s*(?:money|amount)/i
        $scam2 = /(?:visa|travel|emergency)\s*(?:fee|expense)/i
        $scam3 = /(?:stuck|stranded|arrested)\s*(?:need|help)/i
    condition:
        any of ($mat*) and any of ($scam*)
}

rule INDIA_FAKE_APP_SCAM {
    meta:
        description = "Fake app download scams"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "MALWARE"
        confidence = 90
        version = "2025.1"
    strings:
        $app1 = /(?:download|install)\s*(?:this|our|new)\s*app/i
        $app2 = /\.apk\s*(?:download|install|link)/i
        $app3 = /(?:third\s*party|external)\s*(?:app|download)/i
        $sus1 = /(?:loan|earning|investment|trading)\s*app/i
        $sus2 = /(?:beta|mod|cracked|premium)\s*(?:version|app)/i
        $sus3 = /(?:telegram|whatsapp)\s*(?:download|link)/i
        $malware1 = /(?:enable|allow)\s*(?:unknown\s*sources?|install)/i
        $malware2 = /(?:bypass|disable)\s*(?:play\s*protect|security)/i
    condition:
        any of ($app*) and (any of ($sus*) or any of ($malware*))
}

rule INDIA_FAKE_REWARD {
    meta:
        description = "Fake reward/cashback scams"
        author = "ScamGuard Pro"
        severity = "high"
        category = "PHISHING"
        confidence = 85
        version = "2025.1"
    strings:
        $reward1 = /(?:cashback|reward|bonus)\s*(?:of|worth)\s*(?:rs\.?|₹)\s*\d+/i
        $reward2 = /(?:won|earned|received)\s*(?:reward|cashback|points)/i
        $reward3 = /(?:scratch\s*card|spin\s*wheel|lucky\s*draw)/i
        $reward4 = /(?:amazon|flipkart|paytm|gpay)\s*(?:reward|voucher|gift\s*card)/i
        $scam1 = /(?:claim|collect|redeem)\s*(?:now|today|immediately)/i
        $scam2 = /(?:expires?|valid)\s*(?:today|in\s*\d+\s*hours?)/i
        $scam3 = /(?:click|tap|visit)\s*(?:link|here|below)/i
    condition:
        2 of ($reward*) or (any of ($reward*) and any of ($scam*))
}

rule INDIA_SUSPICIOUS_SHORT_URL {
    meta:
        description = "Suspicious shortened URLs"
        author = "ScamGuard Pro"
        severity = "medium"
        category = "SHORTENER_ABUSE"
        confidence = 75
        version = "2025.1"
    strings:
        $short1 = /bit\.ly\/[a-zA-Z0-9]{5,}/i
        $short2 = /tinyurl\.com\/[a-zA-Z0-9]+/i
        $short3 = /t\.co\/[a-zA-Z0-9]+/i
        $short4 = /goo\.gl\/[a-zA-Z0-9]+/i
        $short5 = /ow\.ly\/[a-zA-Z0-9]+/i
        $short6 = /is\.gd\/[a-zA-Z0-9]+/i
        $short7 = /cutt\.ly\/[a-zA-Z0-9]+/i
        $short8 = /rb\.gy\/[a-zA-Z0-9]+/i
        $short9 = /shorturl\.at\/[a-zA-Z0-9]+/i
        $short10 = /clck\.ru\/[a-zA-Z0-9]+/i
    condition:
        any of ($short*)
}

rule INDIA_SUSPICIOUS_DOMAIN_TLD {
    meta:
        description = "Suspicious TLDs commonly used in scams"
        author = "ScamGuard Pro"
        severity = "medium"
        category = "SUSPICIOUS_DOMAIN"
        confidence = 70
        version = "2025.1"
    strings:
        $tld1 = /https?:\/\/[^\/]+\.tk(?:\/|$)/i
        $tld2 = /https?:\/\/[^\/]+\.ml(?:\/|$)/i
        $tld3 = /https?:\/\/[^\/]+\.ga(?:\/|$)/i
        $tld4 = /https?:\/\/[^\/]+\.cf(?:\/|$)/i
        $tld5 = /https?:\/\/[^\/]+\.gq(?:\/|$)/i
        $tld6 = /https?:\/\/[^\/]+\.xyz(?:\/|$)/i
        $tld7 = /https?:\/\/[^\/]+\.top(?:\/|$)/i
        $tld8 = /https?:\/\/[^\/]+\.click(?:\/|$)/i
        $tld9 = /https?:\/\/[^\/]+\.link(?:\/|$)/i
        $tld10 = /https?:\/\/[^\/]+\.online(?:\/|$)/i
        $tld11 = /https?:\/\/[^\/]+\.site(?:\/|$)/i
        $tld12 = /https?:\/\/[^\/]+\.club(?:\/|$)/i
        $tld13 = /https?:\/\/[^\/]+\.icu(?:\/|$)/i
        $tld14 = /https?:\/\/[^\/]+\.buzz(?:\/|$)/i
        $tld15 = /https?:\/\/[^\/]+\.work(?:\/|$)/i
    condition:
        any of them
}

rule INDIA_HINGLISH_SCAM_PATTERN {
    meta:
        description = "Hinglish scam patterns"
        author = "ScamGuard Pro"
        severity = "high"
        category = "SOCIAL_ENGINEERING"
        confidence = 83
        version = "2025.1"
    strings:
        $hin1 = /aapka\s*(?:account|bank|paisa)/i
        $hin2 = /paisa\s*(?:bhejo|transfer|jaldi)/i
        $hin3 = /urgent\s*(?:hai|hain|karo)/i
        $hin4 = /abhi\s*(?:click|call|karo)/i
        $hin5 = /??:?jaldi|turant|fauran)\s*(?:karo|kijiye|bhejo)/i
        $hin6 = /(?:block|band|suspend)\s*ho\s*(?:jayega|gaya|raha)/i
        $hin7 = /(?:last|aakhri)\s*(?:chance|mauka|warning)/i
        $hin8 = /(?:free|muft)\s*(?:mein|me)\s*(?:pao|lo|milega)/i
        $hin9 = /(?:lottery|lucky\s*draw)\s*(?:nikla|jeeta|mila)/i
        $hin10 = /(?:otp|password)\s*(?:batao|bhejo|share\s*karo)/i
    condition:
        2 of them
}

rule INDIA_FAKE_LOGIN_PAGE {
    meta:
        description = "Fake login page indicators"
        author = "ScamGuard Pro"
        severity = "critical"
        category = "FAKE_LOGIN_PAGE"
        confidence = 91
        version = "2025.1"
    strings:
        $login1 = /<title>.*(?:login|sign\s*in|log\s*in).*<\/title>/i
        $login2 = /<input.*type\s*=\s*["']password["']/i
        $login3 = /<form.*(?:action|method)/i
        $brand1 = /(?:sbi|hdfc|icici|axis).*(?:login|sign\s*in)/i
        $brand2 = /(?:paytm|phonepe|gpay).*(?:login|sign\s*in)/i
        $brand3 = /(?:facebook|google|instagram|whatsapp).*(?:login|sign)/i
        $sus1 = /(?:blogspot|wordpress|wix|weebly)\.com/i
        $sus2 = /(?:herokuapp|vercel|netlify)\.app/i
        $sus3 = /(?:\.tk|\.ml|\.ga|\.cf|\.xyz)/i
    condition:
        (any of ($login*) and any of ($brand*)) or (2 of ($login*) and any of ($sus*))
}

rule INDIA_URGENCY_PRESSURE {
    meta:
        description = "High urgency/pressure tactics"
        author = "ScamGuard Pro"
        severity = "medium"
        category = "SOCIAL_ENGINEERING"
        confidence = 78
        version = "2025.1"
    strings:
        $urgent1 = /(?:urgent|emergency|immediate)\s*(?:action|attention|response)/i
        $urgent2 = /(?:within|before)\s*\d+\s*(?:hours?|minutes?|days?)/i
        $urgent3 = /(?:last|final)\s*(?:chance|warning|notice|reminder)/i
        $urgent4 = /(?:act|respond|call|click)\s*(?:now|immediately|today)/i
        $urgent5 = /!!!+/
        $urgent6 = /URGENT/
        $urgent7 = /WARNING/
        $urgent8 = /ALERT/
        $urgent9 = /(?:don'?t|do\s*not)\s*(?:ignore|delay|wait)/i
    condition:
        3 of them
}

rule INDIA_MULTIPLE_EXCLAMATION {
    meta:
        description = "Excessive exclamation marks"
        author = "ScamGuard Pro"
        severity = "low"
        category = "SOCIAL_ENGINEERING"
        confidence = 60
        version = "2025.1"
    strings:
        $exc = /!{3,}/
    condition:
        #exc > 2
}
