# SentinelMesh

**SentinelMesh** is an autonomous, decentralized threat intelligence network that bridges the gap between hardware-level IoT security and immutable blockchain logging. It utilizes edge AI to detect network threats directly at the physical layer, ensuring real-time anomaly classification without cloud dependencies or communication latencies.

---

### **Core Architecture**
* **Edge Intelligence:** Deployed on resource-constrained **ESP32** hardware utilizing **TensorFlow Lite Micro** for on-device attacker and packet anomaly classification.
* **Decentralized Communication:** Inter-node synchronization is handled via **ESP-NOW** (a low-latency, peer-to-peer wireless protocol) to establish a self-healing, infrastructure-less mesh network.
* **Immutable Security Ledger:** Cryptographic incident hashes (SHA-256) are anchored onto the **Polygon Blockchain** using **Web3.py**, establishing a tamper-proof forensic audit trail of all detected attacks.
* **Full-Systems Dashboard:** Consumes high-throughput socket streams into a **React** frontend using **Socket.IO** and **D3.js** for real-time mesh health monitoring and coordinate-based threat visualization.

---

### **Key Features**
* **On-Device Inference:** Mitigates risk vectors by evaluating network packet flows directly on microcontrollers, entirely avoiding cloud round-trip latencies.
* **Infrastructure Resilience:** The P2P mesh network dynamically re-routes threat broadcast packages, remaining fully functional even if multiple nodes are intentionally compromised or taken offline.
* **Cryptographic Evidence Anchoring:** Generates auditable records of security incidents, creating unalterable time-stamped proof vectors ideal for modern enterprise digital forensics.
* **Interactive Live Heatmaps:** Renders high-frequency canvas data through D3 components to let system administrators track threat distribution vectors visually.

---

### **Tech Stack**
* **Hardware & IoT:** ESP32 Microcontrollers, Wireless Transceiver Arrays
* **Edge Intelligence:** TensorFlow Lite Micro, C++, Python (Model Training)
* **Web3 Ecosystem:** Solidity (Smart Contracts), Web3.py, Polygon Testnet Network
* **Backend Systems:** Node.js, Express, Socket.IO
* **Frontend Interface:** React.js, TypeScript, Tailwind CSS, D3.js

---

### **System Workflow**
1. **Packet Evaluation:** Distributed ESP32 nodes capture and analyze localized network packet streams at the hardware interface.
2. **Edge AI Inference:** The embedded TensorFlow Lite Micro runtime evaluates the stream against pre-trained classification weights to flag malicious fingerprints or flooding attacks.
3. **Mesh Broadcast:** Upon trigger confirmation, the compromised node alerts adjacent nodes immediately across the mesh network using P2P ESP-NOW packets.
4. **Blockchain Commit:** An automated bridge worker computes the cryptographic payload digest and records it permanently to the Polygon testnet ledger via a secure Web3.py smart contract call.
5. **Real-Time Render:** The Node.js server broadcasts the event via Socket.IO, shifting the live React + D3 view to update system topologies and flash warning vectors on the admin panel.

---

### **Project Status**
Developed for the **Equinox 2026 Hackathon**. SentinelMesh is a fully functional hardware-and-software prototype proving the validity of trustless, edge-computed IoT security architectures.