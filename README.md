# FoundryBot — Public Internet Bootstrap (Concise)

**FoundryBot** is a foundation builder: one script (`deploy.sh`) lays down the OS, networking, container runtime, and base hardening using the public Internet, then **hands off** cleanly so you can apply configuration with your own stack (Ansible/Salt/Puppet/Chef/custom). WireGuard devices are created and **keys generated** but **no peers are added**; you can import them into an existing mesh or run `apply.py` to stand up the reference Salt‑driven K8s example. The goal is fast, reproducible installs and clear ownership of post‑install policy.

- **Single step**: `bash ./deploy.sh` builds the base world (OS + plumbing); config is separate by design.  
- **Tool‑agnostic**: bring your own automation; `apply.py` is optional and self‑contained.  
- **WG posture**: devices up, keys generated, **no peering by default** (safe to join your own mesh).  
- **K8s‑ready**: runtime and prerequisites in place; running cluster only if you opt‑in via `apply.py`.  
- **Secure defaults**: nftables default‑deny; services bind to intended planes; SSH key‑only.  
- **Rebuild > restore**: treat host OS as disposable—snapshots/replication belong to your storage plane.
