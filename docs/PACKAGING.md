# Packaging & supply chain

How ARGUS is built into installable artifacts, signed, and verified across kernels.

## Linux packages (deb / rpm)

`make package` builds both packages with [nfpm](https://nfpm.goreleaser.com)
from `packaging/nfpm.yaml`. It depends on `make all`, so the binaries and the
compiled eBPF objects exist first.

```bash
make all          # build/bin/{argus,argus-server} + build/*.bpf.o
make package      # -> build/dist/argus_<version>_<arch>.{deb,rpm}
```

Install layout (mirrors the systemd unit and `make install`):

| Path | Contents |
|------|----------|
| `/usr/bin/argus`, `/usr/bin/argus-server` | binaries |
| `/usr/lib/argus/edr.bpf.o`, `edr_lsm.bpf.o` | compiled eBPF objects (loaded at runtime) |
| `/etc/argus/config.yaml` | agent config (`config|noreplace` — an upgrade keeps your edits) |
| `/etc/argus/rules/` | detection rules |
| `/lib/systemd/system/argus.service` | the agent unit |
| `/usr/share/doc/argus/SAFETY.md` | the safety model — read before enabling enforce |

Installing the package **does not arm the agent.** The post-install script only
registers the unit; the agent stays disabled and, once started, observes-only
until you set `response.mode` (see `docs/SAFETY.md`). Start it with
`systemctl enable --now argus`.

## SBOM

`make sbom` runs [syft](https://github.com/anchore/syft) over the source tree and
writes a CycloneDX SBOM to `build/dist/argus.sbom.cdx.json`. The release workflow
generates and publishes it alongside the packages.

## Container image

`deploy/docker/Dockerfile` builds a distroless image containing **both** binaries
(`argus` and `argus-server`), so one tag serves the agent DaemonSet and the
control-plane Deployment. Build it after `make bpf` (the image copies the compiled
object in):

```bash
make bpf
docker build -f deploy/docker/Dockerfile -t ghcr.io/argus-edr/argus:dev .
```

## Helm chart

`deploy/helm/argus` deploys the agent as a privileged DaemonSet (eBPF needs host
kernel access) and, optionally, the control plane as a Deployment.

```bash
helm install argus deploy/helm/argus            # agent only, response mode off
helm install argus deploy/helm/argus \
  --set server.enabled=true --set server.tlsSecret=argus-fleet-certs
```

Safe defaults: `agent.responseMode=off` and `server.enabled=false`. The chart
renders a minimal agent config (`configmap.yaml`) — the agent fills in every other
key from its built-in defaults — and rolls the DaemonSet when that config changes.

## Releases & signing

The `release` workflow fires on a `v*` tag and:

1. builds the eBPF objects and binaries, then `make package`;
2. generates the SBOM (syft);
3. signs each `.deb`/`.rpm`/SBOM with **cosign** keyless (GitHub OIDC — no
   long-lived key), emitting a `.sig` signature and a `.pem` certificate plus a
   `SHA256SUMS`;
4. publishes them all to the GitHub release.

Verify a downloaded package:

```bash
cosign verify-blob --signature argus_*.deb.sig --certificate argus_*.deb.pem \
  --certificate-identity-regexp 'https://github.com/argus-edr/argus/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  argus_*.deb
```

## Kernel-version CI matrix

eBPF portability is verified by the `kernel-matrix` workflow: it compiles the
objects once, then boots a VM at each target kernel (**5.8 / 5.15 / 6.1 / 6.8**)
and runs `scripts/verifier-smoke.sh`, which loads every program and confirms the
verifier accepts it. The sensor object is required on all kernels; the BPF-LSM
object is best-effort (it needs `CONFIG_BPF_LSM`). Run it locally on any BTF
kernel with `sudo make verifier-smoke`.

> The matrix uses `cilium/little-vm-helper` for prebuilt kernel images. Pin the
> action to a digest (not a tag) for release branches, and confirm the
> `image-version` tags exist in the lvh image registry when bumping the window.
