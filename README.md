# FoundryBot

**FoundryBot is a self-deploying kubernetes cluster operating system.**  
It turns bare metal (or a hypervisor) into a complete, secure Kubernetes platform in **one operation**.

No hand-built images.  
No snowflake servers.  
No “day-2” glue scripts.

You boot it — it builds the world.

---

## What FoundryBot Does

FoundryBot deploys an **entire production-grade Kubernetes environment** from scratch in a single run:

- Provisions **16+ virtual machines** (or bare-metal nodes)
- Brings up **secure networking** automatically
- Builds a **multi-node etcd cluster**
- Initializes **high-availability Kubernetes**
- Configures **load balancers, workers, control planes**
- Enables **monitoring, logging, and observability**
- Locks everything down **secure-by-default**

All of this happens **without manual intervention**.

---

## Why FoundryBot Is Different

Most tools *append* configuration onto an existing image.

FoundryBot does not.

> **FoundryBot completely rebuilds and deploys the operating system and the infrastructure in one step.**

### A simple analogy:

- **Packer**:  
  _“Take this image and add some things to it.”_

- **Cloud-init**:  
  _“Boot first, then try to configure.”_

- **FoundryBot**:  
  _“Melt the metal, cast the machine, and bring the entire factory online.”_

The ISO itself is **repacked** with everything it needs — including packages, configuration, and recovery artifacts — and then deployed as a unified system, Simply add your own artifacts and post installers.

---

## Secure Networking by Default (WireGuard)

Every node is connected using **WireGuard**, forming a private, encrypted mesh:

- No exposed internal services
- No flat networks
- No trust by IP alone

Think of it as:

> **A private kernel-level VPN woven directly into the cluster fabric.**

All control traffic, orchestration, and management flows over this encrypted mesh automatically.

---

## Observability Built In (eBPF + Logging)

FoundryBot is designed for **deep visibility**:

- eBPF enables low-overhead, kernel-level observability
- Fine-grained network, syscall, and workload inspection
- Structured logging from day zero
- Designed to integrate with modern log and metrics stacks

Nothing is “bolted on later”.  
Observability is part of the platform.

---

## Storage That Scales

FoundryBot supports **real distributed storage**:

- **OpenZFS** for high-integrity, snapshot-driven systems
- **Ceph** for scalable, fault-tolerant distributed workloads

This allows:
- Stateful Kubernetes workloads
- Durable infrastructure services
- Truly portable clusters

Storage is treated as **infrastructure**, not an afterthought.

---

## Salt & Ansible Are First-Class Citizens

FoundryBot uses both — on purpose.

- **Salt**  
  - Fast discovery  
  - Secure enrollment  
  - Real-time execution  
  - Cluster-wide orchestration  

- **Ansible**  
  - Declarative configuration  
  - Idempotent system builds  
  - Full cluster lifecycle management  

They are not plugins.  
They are **core subsystems** of the platform.

---

## Build Modes

FoundryBot ships with multiple build workflows:

### `deploy.sh`
Brings up the **entire Kubernetes platform** from nothing in one run.

### `build.sh`
Creates a **fully self-contained ISO**:
- All packages
- All configuration
- All artifacts
- Offline / darksite recovery ready

Think of it as a **portable infrastructure snapshot**.

### Cloneable Workloads
FoundryBot can also produce:
- Remote desktops
- Secure workstations
- Specialized environments

These are **point-and-shoot**, fully baked, and can be deployed anywhere — hub-and-spoke style.

---

## What FoundryBot Replaces

FoundryBot collapses the need for:

- Packer
- Cloud-init
- MAAS
- Ad-hoc provisioning scripts
- Manual cluster bootstrapping
- Fragile post-install steps

One system.  
One operation.  
One source of truth.

---

## Philosophy

- **Rebuilds are normal**
- **State is disposable**
- **Security is the default**
- **Clusters are the unit of computation**

FoundryBot doesn’t manage machines.

It **manufactures platforms**.

---

## Status

Active development.  
Designed for real-world infrastructure.  
Built to be torn down and rebuilt repeatedly — on purpose.

---

**FoundryBot**  
*Build the world. Every time.*
