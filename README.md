# 🛡️ Email Safety Checker (Browser Extension)

AI-powered browser extension designed to protect enterprise staff and everyday consumers from sophisticated phishing attacks. It acts as an active shield inside your inbox, instantly analyzing incoming emails and alerting users to dangerous links or spoofed senders before they can click.

Originally conceptualized for enterprise security (e.g., Tata Motors), this tool is being built to scale as a comprehensive **SaaS solution** for general users.

---

## 🛑 The Problem
Inbox clutter and sophisticated social engineering make it difficult for users to distinguish between legitimate communications and dangerous phishing attempts. 
* Users often overlook spoofed email addresses (e.g., mistaking `@microsoft-support.com` for `@microsoft.com`).
* Malicious links are hidden behind legitimate-looking text.
* Accidental clicks lead to compromised corporate data, credential theft, and financial fraud.

## ✨ Core Features (The Solution)
1. **Sender Verification:** Analyzes the sender's domain and headers to determine if the email is genuinely from the claimed organization or if it is a spoofed imposter.
2. **Intelligent Link Checking:** Extracts and scans all URLs within the email body, warning users if a link leads to a known or suspected phishing site.
3. **Traffic-Light Safety Verdicts:** Injects a highly visible, easy-to-understand safety message directly into the email interface:
   * 🟢 **Safe:** Verified sender and clean links.
   * 🟡 **Be Careful:** Unknown sender or suspicious elements detected.
   * 🔴 **Don't Click:** Confirmed phishing attempt or malicious links present.

---

## 🏗️ System Architecture

MailSentinel operates using a dual-engine Machine Learning architecture integrated directly into the user's browser.

### 1. Phishing Link Analysis Model
* **Purpose:** Determines the safety of URLs embedded in the email.
* **Architecture:** Utilizes an **Ensemble Model** (combining 2-3 distinct algorithms such as Random Forest, XGBoost, and a Neural Network). This multi-model approach drastically improves accuracy and reduces false positives.

### 2. Email Content & Sender Analysis Model
* **Purpose:** Evaluates the email text for social engineering patterns (e.g., manufactured urgency) and verifies domain authenticity.

### 3. The Client Interface
* A lightweight, interactive **Browser Extension** (Chrome/Edge/Firefox) that seamlessly bridges the ML models with the user's webmail client (Gmail, Outlook, etc.).

---

## 🚀 Current Status & Roadmap

**Phase 1: Research & Link Model Development (🟢 Currently Here)**
- [x] Define project scope and SaaS scalability.
- [x] Complete dataset research and acquisition for phishing URLs.
- [x] Initial dataset study and preprocessing.
- [ ] Train and fine-tune the initial ML algorithms.
- [ ] Build and optimize the Ensemble Model for link analysis.

**Phase 2: Email Content Model Development (⏳ Upcoming)**
- [ ] Acquire and preprocess email text datasets (spam/phishing vs. ham).
- [ ] Train the NLP model for content analysis.
- [ ] Develop sender verification heuristics.

**Phase 3: Browser Extension Integration (⏳ Upcoming)**
- [ ] Develop the browser extension frontend.
- [ ] Connect the extension to the ML backend via API.
- [ ] Implement the UI overlay (Safe / Be Careful / Don't Click).
- [ ] Beta testing in a live webmail environment.

---

## 🤝 Contributing
As we build out the dual-model architecture, contributions to dataset curation, model tuning, and extension UI design are welcome. Please open an issue to discuss proposed changes before submitting a pull request.
