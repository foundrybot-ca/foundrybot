# FoundryBot

**FoundryBot is an atomic, self-deploying cluster platform.**  
It manufactures a complete, secure, reproducible infrastructure base from raw hardware, hypervisors, or cloud instances — in **one convergent operation**.

No hand-built images.  
No snowflake servers.  
No vendor control planes.  
No “day-2” glue scripts.

You boot it — **it builds the world**. 

---

## What FoundryBot Is

FoundryBot is a **Declarative Cluster Lifecycle Platform** built around a single, uncompromising premise:

> **If infrastructure cannot be rebuilt from nothing, anywhere, at any time, it is already broken.**

FoundryBot produces a **deployable, atomic platform base** — a clean, deterministic foundation that serves as a **reproducible blank canvas** for any workload.

Deployment and configuration are **intentionally and strictly separated**:

- **Deployment** manufactures the platform
- **Configuration** is layered on top, disposable by design

This separation is what enables extreme portability, minimal MTTR, and long-term survivability.

---

## Atomic by Design

FoundryBot is **atomic**.

Each build produces a **complete, self-contained platform artifact** that includes:

- Operating system
- Kernel configuration
- Secure networking fabric
- Identity and trust model
- Automation backends
- Storage primitives
- Observability and telemetry
- Recovery and rebuild artifacts

There are **zero external dependencies** required to complete the system after boot.

The platform either exists — or it doesn’t.

---

## Dark-Site & Time-Capsule Safe

FoundryBot is designed to survive **time**, not just outages.

Everything required to rebuild the platform is **baked into the artifact**:
- All packages
- All versions
- All tooling
- All orchestration logic

No live repositories.  
No broken mirrors.  
No abandoned vendors.  
No silent dependency drift.

> **If your infrastructure explodes five years from now, you can still redeploy it exactly as it was.**

Your **last successful deployment** becomes your **permanent MTTR anchor** — today, tomorrow, and beyond.

Burn it to USB.  
Store it in a safe.  
Walk away.

---

## A Reproducible Blank Canvas

FoundryBot does **not** bake business logic, applications, or environment-specific decisions into the platform.

Instead, it delivers:
- A hardened, minimal attack-surface base
- A known-good control plane
- Deterministic behavior across all substrates

This makes FoundryBot ideal as:
- A Kubernetes substrate
- A storage or database fabric
- A secure internal platform
- An edge or offline deployment base
- A disaster recovery foundation

What you build *on top* is your choice.

---

## Separation of Deployment and Configuration

This is not optional. It is foundational.

### Deployment
- Immutable
- Deterministic
- Auditable
- Reproducible

### Configuration & Workloads
- Disposable
- Replaceable
- Environment-specific
- Drift-resistant

Rebuilds are mechanical.  
Recovery is boring.  
Failure is survivable.

---

## Unmatched MTTR by Construction

FoundryBot is designed for **catastrophic scenarios**, not happy paths:

- Cloud region loss
- Ransomware
- Supply-chain compromise
- Vendor collapse
- Operator error at scale

With FoundryBot:

> **You do not repair infrastructure.  
> You replace it.**

From total failure to fully operational platform is a **predictable, repeatable process**, measured in minutes — not days.

---

## Substrate-Agnostic, Vendor-Free

FoundryBot is **intentionally hostile to vendor lock-in**.

No:
- HashiCorp control planes
- SaaS orchestration layers
- Embedded vendor telemetry
- Proprietary networking overlays

Instead, FoundryBot produces **golden, agnostic platform images** that you control completely.

If AWS us-east disappears:
- Upload the same images to Azure, GCP, or on-prem
- Boot
- Deploy

You get the **same platform**, with the same security posture and behavior — every time.

The substrate is interchangeable.  
The platform is not.

---

## Secure Networking Without SaaS

All nodes participate in a **WireGuard-based encrypted mesh**:

- Kernel-level encryption
- No flat networks
- No trust-by-IP
- No external brokers

No Tailscale.  
No NetBird.  
No recurring bills.

> **A private, cryptographic network fabric built directly into the platform.**

---

## Observability Is a First-Class Citizen

FoundryBot treats observability as **infrastructure**, not an add-on.

Included from first boot:
- eBPF-based kernel introspection
- Network, syscall, and workload visibility
- Structured, machine-readable logging
- Designed for modern metrics and tracing stacks

If something happens, **you can see it**.  
If it breaks, **you can prove why**.

---

## Storage as Infrastructure

FoundryBot integrates storage as a core platform primitive:

- **OpenZFS**
  - Integrity-first
  - Snapshots and rollback
  - Ideal for system and control-plane state

- **Ceph**
  - Distributed
  - Fault-tolerant
  - Designed for stateful workloads

State is protected, portable, and replaceable — not fragile.

---

## Salt & Ansible as Core Subsystems

FoundryBot uses both — intentionally.

### Salt (Bootstrap & Control)
- Secure enrollment
- Fast discovery
- Reliable execution
- Cluster-wide coordination

Salt is used where **speed, identity, and orchestration** matter most.

### Ansible (Post-Configuration & Lifecycle)
- Declarative
- Idempotent
- Auditable
- Familiar

Ansible is **prebuilt into the platform**.  
Add your playbooks — and they simply appear.

No installers.  
No agents.  
No extra tooling.

---

## FoundryBot is **not a Kubernetes installer**.

It is a **cluster operating system and lifecycle platform**.

Kubernetes is included as a reference workload because it makes an **AWESOME** example. 
- Networking
- Identity
- Storage
- Automation
- Observability

If FoundryBot can deterministically manufacture a production-grade, HA Kubernetes cluster, it can manufacture almost anything.

Workloads are replaceable.  
The platform is permanent.

---

## Fully Auditable, From the Ground Up

FoundryBot does not download mystery artifacts or apply opaque transformations.

The entire build process is:
- Transparent
- Auditable
- Deterministic
- À-la-carte

It **builds the operating system from the ground up**, assembles only what is required, and delivers a platform that boots **directly into a fully running state**.

No post-install tools.  
No secondary provisioning systems.  
No hidden steps.

---

## Philosophy

- **Platforms are atomic**
- **Rebuilds are normal**
- **State is disposable**
- **Clusters are the unit of computation**
- **Security is the default**
- **Human intervention is a failure mode**

FoundryBot doesn’t manage machines.

It **manufactures certainty**.

---

## About the Founder

FoundryBot is built by an infrastructure engineer with deep experience across Unix, BSD, Linux, networking, storage, and distributed systems.

After years of operating real production systems, one truth became unavoidable:

> **Most outages are not caused by failure — they are caused by irreproducibility.**

FoundryBot exists so catastrophic failure becomes just another deployment.

---

## Status

Active development.  
Designed for real-world infrastructure.  
Built to be destroyed — and rebuilt — forever.

---

**FoundryBot**  
*Build the world. Every time.*
