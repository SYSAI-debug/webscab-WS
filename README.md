# webscab-

**Advanced Web Security Auditing Tool**

Webscab is a comprehensive and modular web security scanning tool designed to detect vulnerabilities, extract web assets, and perform in-depth analysis to safeguard your web applications. Built with flexibility and ethical usage in mind, Webscab is engineered for professionals who demand advanced capabilities across multiple platforms.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Usage](#usage)
- [Installation](#installation)
  - [Linux / Unix](https://webscab.pages.dev)
  - [Windows (PowerShell)](https://webscab.pages.dev)
  - [Android / Termux](https://webscab.pages.dev)
  - [Other Mobile Linux Devices](https://webscab.pages.dev)
- [Community](https://webscab.pages.dev)
- [Contribution](#contribution)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Overview

Webscab is built to provide security professionals with a flexible environment for web vulnerability scanning. It features multi-threaded scanning, comprehensive asset analysis, and static code assessment—which can be extended with custom modules. Designed to mimic a Linux terminal environment, the tool delivers a smooth command-line experience on Linux, Windows, and mobile Linux distributions via Termux.

---

## Features

- **Modular & Extensible:** Easily integrate new scanning modules.
- **Deep Vulnerability Detection:** Rapid identification of open ports, service banners, and other potential risks.
- **Asset Extraction:** Identify web components and configuration files for detailed analysis.
- **Cross-Platform Compatibility:** Native support for Linux/Unix, Windows, and mobile Linux environments.
- **Community Driven:** Join a growing network of developers and security researchers on GitHub and other platforms.
- **Terminal-Like Experience:** Designed with a dark, Linux terminal aesthetic for maximum usability.

---

## Usage

Run Webscab by specifying the target URL:

```bash
./wscab.py <target_url>
```
After, then run ./scan_webpages_wscab.py tool to get target page assets, including: HTML, CSS, JS
```
./scan_webpages_wscab.py https://example.com/
