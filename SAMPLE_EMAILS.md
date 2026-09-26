# Sample Email Templates for Unity Credit Union

Here are some of the automated emails that your application sends to users and administrators:

## 1. Loan Application Received Email
**Sent to:** Loan Applicant
**When:** Immediately after loan application submission

```
Hello [Applicant Name],

We received your loan application. The administrator will verify it and you will get an email with the decision.

Your loan reference
LN260012
Keep it. You can use it on the Verify loan page.

Loan type          Emergency Loan
Amount             GHS 5,000.00
Interest           10%
You would repay    GHS 5,500.00
Time to repay      35 days

[Verify Loan Button]
```

## 2. Guarantor Notice Email
**Sent to:** Both Guarantors
**When:** Immediately after loan application submission

```
Hello [Guarantor Name],

[Applicant Name] has named you as a guarantor for a loan at Unity Credit Union.

Loan reference      LN260012
Loan type          Emergency Loan
Amount             GHS 5,000.00
Time to repay      35 days

If you did not agree to this, please contact us at once on +233247767438.
```

## 3. Admin Notification - New Loan
**Sent to:** Administrator
**When:** Immediately after loan application submission

```
A new loan application is waiting to be verified.

Reference      LN260012
Applicant      John Doe (non-member)
Loan type      Emergency Loan
Amount         GHS 5,000.00

[Review Loan Button]
```

## 4. Loan Approved Email
**Sent to:** Loan Applicant
**When:** When administrator approves the loan

```
Hello [Applicant Name],

Your loan has been verified and approved.

Reference              LN260012
Loan type              Emergency Loan
Amount                 GHS 5,000.00
Interest               10%
Total to repay         GHS 5,500.00
Due date               25 October 2026

Please pay on or before the due date. Every payment you make is recorded and you will get a receipt by email.
```

## 5. Loan Rejected Email
**Sent to:** Loan Applicant
**When:** When administrator rejects the loan

```
Hello [Applicant Name],

Thank you for applying. We are sorry, but we are not able to approve your loan LN260012 at this time.

Reason: Insufficient guarantor coverage for requested amount.

You are welcome to contact us on +233247767438 to talk about it.
```

## 6. Account Created Email
**Sent to:** New User
**When:** After user registration

```
Hello [User Name],

Thank you for signing up with Unity Credit Union. Your details are waiting for verification by the administrator.

You will get another email as soon as your membership is accepted or if we need to correct something.

What happens next
The administrator checks your Ghana Card and details. This usually takes a short time.
```

## 7. Account Verified Email
**Sent to:** New Member
**When:** When administrator verifies the account

```
Hello [User Name],

Good news. Your membership has been verified. Welcome to Unity Credit Union!

Your UCU account number
UCU240912
UCU, then the year you joined, the month you were verified, and your number in the union. Keep it safe: you need it to guarantee a loan.

You can now sign in to see your savings, receipts and loans.

[Sign In Button]
```

## 8. Password Reset Request Email
**Sent to:** User
**When:** When user requests password reset

```
Hello [User Name],

We received a request to reset your password. Click the button below to choose a new one. The link works for one hour and only once.

[Choose a new password Button]

If you did not ask for this, you can ignore this email. Your password will not change.
```

## 9. Loan Payment Receipt Email
**Sent to:** Loan Applicant
**When:** When a loan payment is made

```
Hello [User Name],

We received your loan payment. This is your receipt.

Amount received
GHS 1,500.00

Receipt number        RCT260045
Loan reference        LN260012
Total repaid so far   GHS 1,500.00
Balance              GHS 4,000.00
```

## 10. Dividend Notice Email
**Sent to:** Member
**When:** When dividends are paid

```
Hello [Member Name],

Your dividend for the 2024 cycle has been paid.

Your savings in the cycle    GHS 10,000.00
Dividend rate                15%
Dividend paid                GHS 1,500.00

Thank you for saving with Unity Credit Union.
```

## 11. Admin Notification - New Signup
**Sent to:** Administrator
**When:** When a new user registers

```
A new user has signed up and is waiting for verification.

Name        John Doe
Email       john.doe@example.com
Phone       +233247767438
UCU Number  (pending verification)

[Review Account Button]
```

## 12. Contact Form Notification
**Sent to:** Administrator
**When:** When someone submits the contact form

```
New message from the contact form.

From:       John Doe
Email:      john.doe@example.com
Phone:      +233247767438
Message:    I would like to inquire about membership requirements...

[View Message Button]
```

## Email Features:

### **Professional Design**
- Clean, professional layout
- Consistent branding with Unity Credit Union colors
- Mobile-responsive design
- Clear call-to-action buttons

### **Security Features**
- Personalized with recipient's name
- Time-sensitive links (password resets expire in 1 hour)
- Verification of guarantor consent
- Reference numbers for tracking

### **User Experience**
- Clear, actionable information
- Receipt numbers for payments
- Loan reference numbers for tracking
- Direct links to relevant pages

### **Automation**
- Sent immediately after relevant actions
- Background sending (doesn't slow down the app)
- Error logging for failed deliveries
- Retry mechanisms for transient failures

## Customization:

All email templates can be customized by editing the files in:
`templates/email_templates/`

Common customizations:
- Update contact information
- Change email tone/style
- Add promotional content
- Modify branding elements
- Add additional links or information

## Email Deliverability:

To ensure emails reach recipients:
- SPF records configured for your domain
- DKIM authentication (recommended)
- DMARC policy (recommended)
- Regular monitoring of delivery rates
- Spam folder placement monitoring

All emails are sent from your configured mail server (mail.raydexhub.com) with the sender address set to your configured email address.
