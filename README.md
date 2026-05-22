# Sentinelmesh
SentinelMesh is an autonomous, decentralized threat intelligence network that bridges the gap between hardware-level IoT security and immutable blockchain logging. It utilizes edge AI to detect threats at the source, ensuring real-time response without cloud latency.

Core Architecture
Edge Intelligence: Deployed on ESP32 hardware utilizing TensorFlow Lite Micro for on-device attacker classification.

Decentralized Communication: Nodes communicate via ESP-NOW (a low-latency, peer-to-peer wireless protocol) to create a self-healing mesh network.

Immutable Logging: Security incident metadata is hashed (SHA-256) and anchored onto the Polygon Blockchain using Web3.py, providing a tamper-proof audit trail of network threats.

Visualization: A real-time React + Socket.IO dashboard featuring a D3.js attack heatmap to visualize network integrity.

Key Features
Zero-Latency Detection: On-device inference eliminates the security risks and delays of cloud-based processing.

Mesh Resilience: The network maintains operations even if individual nodes go offline.

Evidence Anchoring: Cryptographic verification of every detected incident, ideal for forensic analysis.

Interactive Monitoring: Live monitoring dashboard for immediate visibility into network node health and threat status.

Tech Stack
Hardware: ESP32, Wireless IoT Sensors

AI/ML: TensorFlow Lite Micro (Edge Inference)

Blockchain: Solidity (Smart Contracts), Web3.py (Integration), Polygon Network

Backend: Node.js, Socket.IO

Frontend: React.js, Tailwind CSS, D3.js

How it Works
Detection: ESP32 nodes monitor local traffic/sensor patterns.

Classification: Edge AI models identify potential threats immediately on the chip.

Communication: Threat alerts are broadcast across the mesh via ESP-NOW.

Anchoring: An automated script hashes the threat event and updates the Polygon blockchain.

Reporting: The React dashboard consumes socket events to update the real-time heat map.