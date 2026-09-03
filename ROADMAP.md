# HELIOS-NET :: Official Project Roadmap

This roadmap outlines the future evolution phases for **HELIOS-NET**, detailing upcoming elite capabilities and architectural milestones.

---

## 🚀 Phase 1: Decentralized Mesh Coordination (Target: Q3 2026)
* **Objective:** Transition from single-node orchestration to a decentralized coordination mesh.
* **Milestones:**
  - [ ] Implement secure P2P node discovery in Go.
  - [ ] Add end-to-end encrypted channel encryption for inter-node communication.
  - [ ] Enable automatic failover and load balancing across active mesh nodes.

---

## 🛡️ Phase 2: Advanced User-Mode Evasion & OPSEC (Target: Q4 2026)
* **Objective:** Harden user-mode evasion primitives to operate under modern EDR/AV instrumentation.
* **Milestones:**
  - [ ] Implement indirect syscalls with dynamically resolved NTDLL SSNs (no hardcoded offsets).
  - [ ] Add advanced API unhooking (NTDLL / kernel32 restorative stubs).
  - [ ] Introduce in-memory encryption of sensitive regions with runtime lazy decryption.
  - [ ] Add randomized module-load ordering and timing jitter to reduce behavioral fingerprinting.

---

## 🧠 Phase 3: Heuristic Finding & Adaptive Verification (Target: Q1 2027)
* **Objective:** Integrate local reasoning loops for automated weakness detection in authorized scopes.
* **Milestones:**
  - [ ] Integrate lightweight local heuristic reasoning modules.
  - [ ] Implement automated logic and misconfiguration inference from raw web/service responses.
  - [ ] Expand verdict rule engine with dynamic contextual learning.

---

## 📡 Phase 4: Non-IP Asset Discovery (Target: Q2 2027)
* **Objective:** Expand asset discovery scope beyond traditional IP/TCP networks.
* **Milestones:**
  - [ ] Add Software Defined Radio (SDR) integration modules in C/Python.
  - [ ] Implement Wi-Fi probe and Bluetooth proximity asset detection sensors.
  - [ ] Map wireless and RF nodes directly into the Asset Graph topology.
