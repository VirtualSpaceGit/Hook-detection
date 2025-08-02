# Hook detection 🛡️

[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Welcome to the Proof of Concept (PoC) for **VirtualSpace Anti-Tampering Protection**, an advanced security monitoring code to detect unauthorized changes, suspicious activities, and hook detection in real-time.

---

## 📌 Overview

The **Anti-Tampering Protection** code continuously monitors system integrity and detects unauthorized modifications or hooks in critical APIs, ensuring robust real-time security. This repo is a Proof Of Concept, and therefore not the real production code. This code is an example of how hooks are detected (not restored).

## 💎 Features

* **Real-time Hook Detection:** Instantly detects API hooking attempts or suspicious alterations.
* **Detailed Monitoring:** Continuously monitors critical system functions for signs of tampering.
* **Real-time Alerts:** Immediate console alerts upon detection of suspicious activity.
* **Clear Reporting:** Provides detailed reports of hook types and affected functions.

## 🔍 How It Works

The Anti-Tampering system employs advanced detection techniques to monitor crucial APIs within the OS:

1. **Initialization:**

   * Identifies and records the clean state of critical system functions.

2. **Continuous Monitoring:**

   * Scans functions at regular intervals for signs of tampering or hooking.
   * Identifies hook types, including JMP Hooks, CALL Hooks, PUSH-RET Hooks, and more.

3. **Real-time Alerting:**

   * Outputs immediate alerts detailing detected hooks, including module and function names.

## 🧪 Usage

* Compile and run the provided main.cpp C++ application.
* The system will start continuous monitoring every 4 seconds by default.
* Attach a debugger like [x64dbg](https://x64dbg.com/) with scyllahide enabled to this application.
* Observe real-time hook detection alerts and detailed reports in the console.

### Console Example

```
[!] NEW HOOK DETECTED [12:30:15] ntdll.dll!NtQueryInformationProcess (JMP Hook (0xE9))
```

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
