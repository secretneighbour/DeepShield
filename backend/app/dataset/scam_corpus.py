"""
Curated dataset of legitimate and scam messages across various categories for
training and evaluating the DeepShield text detection pipeline.
"""

TRAINING_DATA = [
    # --- Benign / Legitimate Messages ---
    {"text": "Hey Mom, just letting you know I arrived safely at the hotel. Will call you around 7 PM after dinner.", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Your Amazon order #402-182937 has shipped via UPS tracking 1Z9999999999999999. Expected delivery Thursday.", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Doctor appointment reminder: Tomorrow at 10:30 AM with Dr. Smith. Reply YES to confirm or call 555-0199 to reschedule.", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Can we meet tomorrow at 2 PM in conference room B to discuss the Q3 engineering roadmap?", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Your monthly utility statement is ready to view. Sign in securely at your regular utility portal.", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Hey, are we still playing basketball this Sunday at the community center?", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Library notice: The book you reserved 'Clean Code' is ready for pickup at the main branch.", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Dinner was great tonight, thanks so much for organizing! Let's do it again next month.", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Your flight AA1234 to Chicago is on time. Gate departure C12. Boarding begins at 3:15 PM.", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Your prescription is ready for pickup at Walgreens on Elm Street.", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Team meeting notes from this morning's retro have been added to the Confluence space.", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Hi David, thanks for sending over the pull request. Left a few comments on line 42.", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Good morning team, the production deploy went smoothly last night without downtime.", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Your Uber driver is arriving in a Toyota Camry license 7ABC123.", "label": 0, "category": "Legitimate / Benign Communication"},
    {"text": "Reminder: School parent-teacher conferences are scheduled for this Thursday evening.", "label": 0, "category": "Legitimate / Benign Communication"},

    # --- Financial / Investment Scams ---
    {"text": "Guaranteed 300% return in 48 hours! Join our exclusive VIP Telegram crypto trading signals group. Deposit $500 Bitcoin now to start compounding daily profits risk-free.", "label": 1, "category": "Financial / Investment Scam"},
    {"text": "Secret AI algorithmic trading bot generates $2,500 daily passive income while you sleep. Zero risk, guaranteed returns. Wire funds to activate your institutional tier.", "label": 1, "category": "Financial / Investment Scam"},
    {"text": "Double your Bitcoin! Elon Musk official Tesla giveaway. Send 0.1 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and receive 0.2 BTC back instantly.", "label": 1, "category": "Financial / Investment Scam"},
    {"text": "Private wealth manager opportunity: invest in pre-IPO shares with 10x guaranteed multiplier. Contact via WhatsApp +192837482 to wire deposit.", "label": 1, "category": "Financial / Investment Scam"},

    # --- Phishing / Credential Harvesting ---
    {"text": "CHASE BANK SECURITY ALERT: Unusual login detected from Moscow. Your account has been temporarily restricted. Verify your identity immediately at http://chase-security-verify.net/login to prevent permanent suspension.", "label": 1, "category": "Phishing / Credential Harvesting"},
    {"text": "PAYPAL: Unauthorized transaction of $699.99 to Best Buy pending. If you did not make this purchase, click http://paypal-resolution-dispute.top/cancel to reverse charges now.", "label": 1, "category": "Phishing / Credential Harvesting"},
    {"text": "Microsoft 365: Your password expires today in 2 hours. Keep current password by signing in here: http://office365-session-renewal.info/auth.", "label": 1, "category": "Phishing / Credential Harvesting"},
    {"text": "Apple ID locked due to suspicious activity. Unlock your iCloud account and update payment details at http://apple-id-recovery-support.xyz/validate.", "label": 1, "category": "Phishing / Credential Harvesting"},
    {"text": "Netflix billing failure: We couldn't process your payment. Update your credit card info within 24 hours at http://netflix-member-update.site/pay to avoid cancellation.", "label": 1, "category": "Phishing / Credential Harvesting"},

    # --- Authority / Executive Impersonation ---
    {"text": "IRS FINAL NOTICE: Legal action has been filed under your SSN for unpaid tax arrears. A federal warrant will be issued for your arrest within 45 minutes unless you call our federal agent immediately.", "label": 1, "category": "Authority / Executive Impersonation"},
    {"text": "Hi, this is Mark, your CEO. I am currently in an urgent confidential board meeting and cannot take calls. I need you to purchase 5 Apple gift cards of $200 each and email me the redemption codes immediately.", "label": 1, "category": "Authority / Executive Impersonation"},
    {"text": "Department of Homeland Security: Your passport and national identity have been linked to an international package containing contraband. Contact officer Johnson immediately to clear your name.", "label": 1, "category": "Authority / Executive Impersonation"},
    {"text": "Geek Squad Support: Your auto-renewal of $499.00 has been charged. To cancel and request an instant refund, call our toll-free helpdesk at 1-888-555-0192.", "label": 1, "category": "Authority / Executive Impersonation"},

    # --- Urgency / Extortion / Blackmail ---
    {"text": "I have installed Pegasus malware on your device and recorded video of you visiting adult sites. Pay $1,200 in Bitcoin to my wallet within 24 hours or I will send the recording to all your family and Facebook contacts.", "label": 1, "category": "Urgency / Threat / Blackmail"},
    {"text": "CRITICAL WARNING: Your device has been compromised by Trojan-Spy.Win32. All files will be permanently encrypted in 6 hours unless you transfer $500 to our recovery wallet.", "label": 1, "category": "Urgency / Threat / Blackmail"},

    # --- Lottery / Prize Scams ---
    {"text": "CONGRATULATIONS! Your mobile number won $1,000,000.00 in the Mega Millions International Mobile Lottery. Send your full name, bank details, and $250 courier fee to claim your cash check.", "label": 1, "category": "Lottery / Prize / Crypto Giveaway"},
    {"text": "Amazon shopper loyalty reward: You have been selected as today's winner of an iPhone 15 Pro Max. Claim your free gift now: pay only $1.95 shipping at http://amazon-gift-winner.club.", "label": 1, "category": "Lottery / Prize / Crypto Giveaway"},

    # --- Job / Task / Employment Scams ---
    {"text": "Work from home part-time: Earn $300-$800 per day by rating products and reviewing apps on our platform. No experience required. Telegram message @hr_recruiter_global to get daily commission.", "label": 1, "category": "Job / Employment / Task Scam"},
    {"text": "Google Global Recruitment: Remote data entry clerk needed. $45/hour. We will send you an initial cashier's check to purchase home office equipment from our approved vendor.", "label": 1, "category": "Job / Employment / Task Scam"},

    # --- OTP / MFA Authentication Theft ---
    {"text": "Bank of America: Do not share this code. 482910 is your one-time verification passcode. A customer service representative will call you in 1 minute to verify this number.", "label": 1, "category": "OTP / MFA Authentication Theft"},
    {"text": "Google Verification Code: 938210. An engineer is verifying your account recovery request. Please text this code back to confirm you are the account owner.", "label": 1, "category": "OTP / MFA Authentication Theft"},

    # --- Advance Fee / Package Delivery / Romance ---
    {"text": "USPS ALERT: Your parcel #US982341 could not be delivered due to an incorrect house number. Update your delivery address and pay the $0.99 redelivery fee at http://usps-redelivery-package.top.", "label": 1, "category": "Phishing / Credential Harvesting"},
    {"text": "Dearest, I am Captain James stationed abroad in a peacekeeping mission. I have a box containing gold bullion worth millions that I need to send to your address for safekeeping. Please wire $1,500 for customs clearance.", "label": 1, "category": "Advance Fee / Romance Scam"}
]

# Benchmark evaluation dataset with strictly held-out test cases
EVALUATION_DATA = [
    # Benign test cases
    {"text": "Hey Sarah, let me know when you get home so we can order pizza for movie night.", "expected_label": 0, "expected_category": "Legitimate / Benign Communication"},
    {"text": "Your prescription at CVS Pharmacy #1042 is filled and ready for pickup.", "expected_label": 0, "expected_category": "Legitimate / Benign Communication"},
    {"text": "Reminder: Your appointment with Dr. Chen is tomorrow at 3:00 PM. Please bring your insurance card.", "expected_label": 0, "expected_category": "Legitimate / Benign Communication"},
    {"text": "Thanks for your GitHub contribution to the scamshield repository! We reviewed your PR and merged it.", "expected_label": 0, "expected_category": "Legitimate / Benign Communication"},
    {"text": "The quarterly financial report has been uploaded to the investor relations secure drive.", "expected_label": 0, "expected_category": "Legitimate / Benign Communication"},

    # Scam test cases
    {"text": "URGENT IRS Notice: A criminal complaint is issued against you. Call 1-800-555-0123 immediately or police will arrest you within 1 hour.", "expected_label": 1, "expected_category": "Authority / Executive Impersonation"},
    {"text": "Wells Fargo: Your online banking is suspended. Restore access immediately by verifying your social security number and debit card at http://wellsfargo-secure-login.xyz.", "expected_label": 1, "expected_category": "Phishing / Credential Harvesting"},
    {"text": "Invest $250 today in our automated crypto matrix and withdraw $10,000 guaranteed profit tomorrow! 100% risk free returns.", "expected_label": 1, "expected_category": "Financial / Investment Scam"},
    {"text": "FedEx: Package delivery failed due to missing street address. Confirm your address and pay $1.50 processing fee at http://fedex-parcel-update.top to release shipment.", "expected_label": 1, "expected_category": "Phishing / Credential Harvesting"},
    {"text": "Send me your 6-digit WhatsApp verification code right now so I can fix your account from the server side.", "expected_label": 1, "expected_category": "OTP / MFA Authentication Theft"},
    {"text": "I have compromised your webcam and have embarrassing video footage of you. Send 0.05 BTC to my address within 48 hours or I will leak it to your employer.", "expected_label": 1, "expected_category": "Urgency / Threat / Blackmail"},
    {"text": "You won the Coca-Cola 2026 Anniversary Lucky Draw! Prize: $500,000. Send processing fee $300 via Western Union to claim your winning certificate.", "expected_label": 1, "expected_category": "Lottery / Prize / Crypto Giveaway"},
    {"text": "Hi, I am CEO Robert. I need you to purchase twenty $100 Steam gift cards for client gifts right now and email me the PIN codes.", "expected_label": 1, "expected_category": "Authority / Executive Impersonation"}
]
