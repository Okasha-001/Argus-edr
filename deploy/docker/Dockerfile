# Runtime image for the ARGUS agent.
#
# The eBPF object (build/edr.bpf.o) must be compiled on a machine with the eBPF
# toolchain first — run `make bpf` before `docker build`. The Go binary is built
# here and needs no CGO or clang.
#
# At runtime the container needs access to the host kernel:
#   docker run --privileged --pid=host -v /sys/kernel/btf:/sys/kernel/btf:ro argus

FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/argus ./cmd/argus

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/argus /usr/local/bin/argus
COPY build/edr.bpf.o /usr/lib/argus/edr.bpf.o
COPY rules /etc/argus/rules
COPY configs/argus.yaml /etc/argus/config.yaml
ENTRYPOINT ["/usr/local/bin/argus", "run", "--config", "/etc/argus/config.yaml"]
