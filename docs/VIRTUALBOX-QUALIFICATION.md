# Fresh VM qualification on a Windows workstation

`scripts/qualify-virtualbox.py` creates a uniquely named disposable guest from an Ubuntu cloud image, attaches a NoCloud seed, copies the release package and executes `scripts/qualify-fresh-vm.sh` followed by `scripts/qualify-linux-service.sh` inside the guest. The installed VirtualBox CLI, OpenSSH, Python and `pycdlib` are prerequisites. The default guest uses 2 GiB RAM and one vCPU. SSH is forwarded on a dynamically selected loopback port. The WAF and its administration listener stay on guest loopback.

Download the amd64 VMDK and SHA256SUMS from the matching official Ubuntu release directory. The runner checks the image against the manifest before creating the guest. The manifest comes from the HTTPS release endpoint. This check does not authenticate a separately signed release manifest. [Ubuntu 22.04 images](https://cloud-images.ubuntu.com/releases/jammy/release/), [Ubuntu 24.04 images](https://cloud-images.ubuntu.com/releases/noble/release/)

```powershell
python scripts/qualify-virtualbox.py --release 24.04 `
  --image artifacts/m2-vms/ubuntu-24.04.vmdk `
  --checksums artifacts/m2-vms/SHA256SUMS-24 `
  --package artifacts/openwaf-m2-20261103-r3-linux-amd64.tar.gz `
  --disposable-vm
```

Use release `22.04` and matching inputs for the other distribution. `--vbox` selects an alternate VBoxManage executable. `--cpus` accepts one or two. The guest script refuses WSL, existing installation paths and an existing OpenWAF service identity. The host runner creates a new guest for each invocation and operates only on its generated VM name.

Each run writes `qualification.log`, `serial.log` and `result.json` beneath `artifacts/m2-vms/openwaf-m2-*`. Results include image, package and guest-script hashes. The log captures guest OS information and the fresh-install/recovery result. The runner stops the guest after completion or failure and retains its registered VM and disk for inspection. Preserve failure logs when retrying. The same directory holds a private SSH key, and the guest disk contains disposable administrator credentials. Keep these artifacts private and exclude them from source publication. Retire the generated VMs and their associated disks deliberately after retaining redacted qualification evidence.

After the 3 November runs, automatic approval review rejected the attempted VM/artifact retirement with `blocked by policy`. The generated guests are stopped, and their private artifacts remain in `artifacts/m2-vms`.

The initial two-vCPU run on this Hyper-V-enabled Windows host produced a guest CPU soft-lockup warning. A one-vCPU guest is the default for repeatability here. This workstation-specific observation requires recording alongside the supported deployment matrix. Native ARM64 still requires a separate native runner.

The seed format and VM controls follow the upstream documentation. [cloud-init NoCloud](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html), [VirtualBox CLI](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/vboxmanage.html)

## Longer fault soaks

`waf-soak` accepts durations from ten seconds through 24 hours, with a preflight ceiling of one million scheduled requests. A duration/rate combination exceeding that budget is refused before creating state. Use a lower rate for longer runs. The manual M2 CI workflow defaults to 120 minutes and accepts up to 240 minutes at 50 requests per second.

```powershell
go run ./cmd/waf-soak -duration 2h -rate 25 -applications 2 -audit-export `
  -cycle 60s -outage 15s -restart 10m -out artifacts/m2-soak-2h.json
```

Completion requires drained exports, equal observed/committed/received security occurrences, equal source/receiver audit counts, empty invariant failures and no unexpected traffic or persistence failures. The harness shares a process between components. Multi-hour duration evidence leaves isolated process RSS/CPU/latency sizing and representative application traffic as separate gates. [M2 qualification](M2-QUALIFICATION.md)
