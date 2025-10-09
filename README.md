# CommieNet(Synapse)
>>A framework that is reimagining resource sharing in university/campus.
>>At CommieNet we plan to make resource sharing more feasible and accessible for students.

Project Proposal: Decentralized Intranet Resource-Sharing Platform

1. Project Overview
Modern organizations often under-utilize computing and storage resources across departments and labs.
This project proposes the development of a private peer-to-peer (P2P) infrastructure that allows nodes on an intranet to discover each other, share storage, and execute compute jobs without a central server.
The system will enable secure, fault-tolerant, and efficient use of existing hardware while remaining fully isolated from the public internet.

2. Objectives
Build a private P2P overlay network for automatic node discovery and secure communication.
Implement distributed storage so that files added on any node are available to all peers.
Provide a compute-sharing layer that schedules and executes containerised jobs across available machines.
Ensure data confidentiality and node authentication through strong cryptography.
Deliver a scalable proof-of-concept (PoC) that can expand to additional nodes or future incentive models.

3. Scope
Intranet only: All traffic remains inside the organization’s private network.
Resources shared:
Disk storage (for file hosting and retrieval)
CPU/GPU cycles for lightweight batch jobs
Out of scope (for initial phase): Public blockchain integration, complex billing mechanisms, wide-area deployment.

4. System Architecture
Layers & Components
P2P Networking Daemon
Built in Go using libp2p for peer discovery (mDNS) and encrypted communication.
Distributed Storage
IPFS private network with a shared swarm.key for content-addressed file sharing.
Compute Runner
Docker Engine API to launch sandboxed jobs on volunteer nodes.
Simple scheduler (round-robin or resource-aware) integrated into the daemon.
Security & Authentication
Mutual TLS using an internal Certificate Authority.
Optional role-based access control for different departments.

5. Technology Stack
Layer	Tools / Frameworks
Language	Go
P2P Networking	libp2p
Storage	IPFS (private mode)
Compute	Docker, Docker Engine API
Security	TLS, internal PKI
Monitoring	Prometheus, Grafana (optional)
Deployment	Linux servers/VMs, Docker Compose
