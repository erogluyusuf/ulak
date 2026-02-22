<div align="center">
  <h1>Ulak</h1>
  <p><b>Intelligent Log Analyzer & 5W1H Diagnostic Engine</b></p>

  [![Project Status](https://img.shields.io/badge/Status-Active_Development-brightgreen)](https://github.com/erogluyusuf/ulak)
  [![Platform](https://img.shields.io/badge/Platform-Linux%20%2F%20Docker-lightgrey)](#)
  [![License](https://img.shields.io/badge/License-MIT-blue)](LICENSE)
  <br>
  ![Python](https://img.shields.io/badge/Backend-Python-green)
  ![AI](https://img.shields.io/badge/AI-Ollama%20%7C%20Local_LLM-orange)
  ![Docker](https://img.shields.io/badge/Deployment-Docker-2496ED?logo=docker&logoColor=white)
</div>

---

>  **Notice:** **Ulak** is currently under **active development**. The architecture is highly experimental and the application is **not yet ready for production use.**

##  About
**Ulak** (Turkish for *Messenger*) is a lightweight, AI-powered log collection and analysis system. Instead of manually parsing through endless system, network, and application logs, Ulak captures them and uses a local Large Language Model (via Ollama) to automatically generate **5W1H** (Who, What, Where, When, Why, How) diagnostic reports. 

It aims to tell you not just *what* crashed, but *why* it happened and *how* to fix it—all while running completely locally and privately via Docker.

##  Planned Features
- **Centralized Ingestion:** Captures OS (`journalctl`, `syslog`), Network, and App logs.
- **Privacy-First AI:** Analyzes errors using local LLMs without sending sensitive system data to external APIs.
- **5W1H Diagnostic Reports:** Translates cryptic error codes into actionable, human-readable insight cards.
- **Containerized:** Designed to deploy seamlessly via Docker Compose with minimal resource overhead.

##  Architecture
The system relies on a Python-based collector that streams filtered logs to a local AI engine, which then processes the context and outputs structured JSON reports.

*(More details will be added to `docs/architecture.md` as development progresses.)*

## 📄 License
Distributed under the MIT License. See `LICENSE` for more information.