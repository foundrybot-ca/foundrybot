# FoundryBot

**FoundryBot is an atomic, self-deploying cluster platform.**  
It turns bare metal, hypervisors, or cloud infrastructure into a **reproducible, secure base platform** in a single convergent operation.

No hand-built images.  
No snowflake servers.  
No “day-2” glue scripts.

You boot it — **it builds the world**.

---

## What FoundryBot Is

FoundryBot is a **Declarative Cluster Lifecycle Platform** designed around a simple but uncompromising idea:

> **Infrastructure should be rebuildable from nothing, anywhere, at any time.**

FoundryBot produces a **deployable, atomic platform base** — a clean, deterministic foundation that serves as a **blank canvas** for any workload.

Deployment and configuration are **intentionally separated**:
- Deployment manufactures the platform
- Configuration and workloads are layered on top

This separation is what enables extreme reproducibility, portability, and recovery speed.

---

## Atomic by Design

FoundryBot is **atomic**.

Each build produces a **complete, self-contained platform image** that includes:
- Operating system
- Networking model
- Identity and trust
- Automation backends
- Storage primitives
- Observability foundations
- Recovery artifacts

There are no external dependencies required to “finish” the system after boot.

The platform either exists — or it doesn’t.

---

## A Reproducible Blank Canvas

FoundryBot does **not** bake business logic, applications, or environment-specific configuration into the platform.

Instead, it delivers:
- A hardened, minimal attack-surface base
- A known-good control plane
- Deterministic behavior across environments

This makes FoundryBot ideal as:
- A Kubernetes substrate
- A storage or database fabric
- A secure internal platform
- An edge or offline deployment base
- A disaster recovery foundation

What you build *on top* is your choice.

---

## Separation of Deployment and Configuration

This is a core design principle.

- **Deployment**  
  - Manufacturing the platform  
  - Deterministic  
  - Immutable  
  - Repeatable  

- **Configuration & Workloads**  
  - Applied after deployment  
  - Disposable  
  - Replaceable  
  - Environment-specific  

Because of this separation:
- Rebuilds are trivial
- Drift is eliminated
- Recovery does not depend on fragile state

---

## Why MTTR Matters

FoundryBot is built for **unmatched Mean Time To Recovery (MTTR)**.

Consider the worst cases:
- Cloud region loss
- Ransomware
- Supply chain compromise
- Catastrophic operator error

With FoundryBot:

> **You don’t repair infrastructure.  
> You replace it.**

---

## Substrate-Agnostic by Default

FoundryBot is designed to be **infrastructure-agnostic**.

If AWS us-east is gone tomorrow:
- Upload the images to Azure, GCP, or on-prem
- Boot
- Redeploy

You get the **same platform**, with the same behavior, security model, and operational characteristics — in under an hour.

The substrate does not matter.  
The platform does.

---

## Disaster Recovery You Can Actually Trust

FoundryBot radically simplifies disaster recovery:

- Burn a small number of USB keys
- Store them in a safe or safety deposit box
- Walk away

No runbooks.  
No tribal knowledge.  
No late-night panic.

From catastrophic failure to a fully operational platform is a **predictable, mechanical process**.

---

## Sleep-At-Night Infrastructure

FoundryBot exists for one reason:

> **So you never have to wonder if you can rebuild your business.**

No more:
- “Did we remember to back that up?”
- “What if this region is gone?”
- “What if everything is compromised?”
- “Can we survive this?”

You already know the answer.

---

## FoundryBot Is a Platform — Kubernetes Is an Example

FoundryBot is **not a Kubernetes installer**.

It is a **cluster operating system and lifecycle platform**.

Kubernetes is included as an **example workload** because it stresses every subsystem at once:
- Networking
- Identity
- Storage
- Automation
- Observability

If FoundryBot can manufacture a production-grade, HA Kubernetes cluster deterministically, it can manufacture almost anything.

The workload is replaceable.  
The platform is not.

---

## Secure Networking by Default

All nodes participate in a **WireGuard-backed encrypted mesh**:

- No exposed internal services
- No flat networks
- No trust by IP alone

> **A private, kernel-level network fabric woven directly into the platform.**

---

## Observability from Day Zero

FoundryBot includes observability as part of the platform contract:

- eBPF-based kernel visibility
- Low-overhead tracing
- Structured logging
- Designed for modern metrics pipelines

Nothing critical is added later.  
Visibility exists before failure does.

---

## Storage as Infrastructure

FoundryBot treats storage as a first-class system component.

Supported models include:
- **OpenZFS** for integrity, snapshots, and rollback
- **Ceph** for distributed, fault-tolerant storage

State is protected, portable, and replaceable.

---

## Build & Target Model

FoundryBot is intentionally split into two roles:

### Build Machine
- Rebuilds installer ISOs from scratch
- Bakes all artifacts and recovery payloads
- Produces final, bootable images

### Target
- Bare metal
- Proxmox
- Cloud (AWS, Azure, etc.)
- Firecracker microVMs

This separation enables:
- Offline installs
- Deterministic rebuilds
- Point-and-shoot deployments
- True platform portability

---

## Philosophy

- **Rebuilds are normal**
- **State is disposable**
- **Platforms are atomic**
- **Clusters are the unit of computation**
- **Security is the default**
- **Human intervention is a failure mode**

FoundryBot doesn’t manage machines.

It **manufactures platforms**.

---

## About the Founder

FoundryBot is built by an infrastructure engineer with deep experience across Unix, BSD, Linux, networking, storage, and distributed systems.

After years of operating real production systems, one truth became unavoidable:

> **Most outages aren’t caused by failure — they’re caused by irreproducibility.**

FoundryBot was built so that catastrophic failure becomes just another deployment.

---

## Status

Active development.  
Designed for real-world infrastructure.  
Built to be destroyed — and rebuilt — on purpose.

---

**FoundryBot**  
*Build the world. Every time.*
