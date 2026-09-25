# FortifyGen 🛡️

A sleek, cryptographically secure password generator built with modern Glassmorphism UI. FortifyGen runs 100% client-side in your browser, ensuring your generated passwords never leave your device.

Available both as a **Chrome Extension (Manifest V3)** and a **standalone Mobile Web App**.

---

## ✨ Features

* **🔒 Cryptographically Secure:** Uses `window.crypto.getRandomValues()` rather than `Math.random()` to generate cryptographically strong, unguessable random passwords.
* **🎯 Guaranteed Variety:** Enforces rules to ensure at least one character from every selected set (Uppercase, Lowercase, Numbers, Symbols) is present, shuffled via the Fisher-Yates algorithm.
* **🎨 Glassmorphism UI:** Modern translucent dark design with an integrated Light/Dark mode switcher.
* **👁️ Password Masking:** Toggle visibility to conceal passwords from shoulder surfers while keeping clipboard copy functionality intact.
* **📱 Mobile & Desktop Friendly:** Optimized for quick access as a browser extension or as a home screen web app on Android & iOS.
* **🛡️ Zero Tracking / 100% Private:** Operates entirely offline without external dependencies, remote servers, or telemetry.

---

## 🛠️ Installation & Setup

### 1. Desktop Chrome Extension

1. Clone or download this repository.
2. Open Google Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** using the toggle in the top-right corner.
4. Click **Load unpacked** in the top-left corner.
5. Select the folder containing `manifest.json`, `popup.html`, and `popup.js`.
6. Pin **FortifyGen** to your browser toolbar for quick access!

### 2. Mobile Home Screen App (Android & iOS)

1. Enable **GitHub Pages** for this repository (`Settings` > `Pages` > Set branch to `main` and folder to `/root`).
2. Open your GitHub Pages URL (e.g., `https://<your-username>.github.io/fortifygen/`) on your mobile browser.
3. Tap your browser menu (⋮ in Chrome or Share in Safari) and select **Add to Home Screen**.
4. Launch FortifyGen anytime as a standalone app!

---

## 🔒 Security & Privacy

FortifyGen was designed with security as the top priority:
* **No Network Requests:** The app does not connect to any API or external server.
* **No Storage of Passwords:** Passwords are generated on-the-fly and lost as soon as you generate a new one or close the window.
* **Client-Side Only:** All operations run locally inside your browser's JavaScript engine.

---

## 🧰 Tech Stack

* **HTML5** & **Vanilla CSS3** (CSS Custom Properties, Glassmorphism backdrop filters)
* **JavaScript (ES6+)** (Web Crypto API, Fisher-Yates shuffle)
* **Chrome Extensions API** (Manifest V3)

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).