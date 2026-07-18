# ÁBACO benchmark image.
#
# The point of running under Docker is HARD resource limits: GOMEMLIMIT is only a
# soft target for the Go GC, so a defensible "runs in 1 GB / 2 cores" result must
# come from cgroups. Run, for example:
#
#   docker build -t abaco .
#   docker run --rm --memory=1g --cpus=2 abaco bench --votes 1000000 \
#       --cores 2 --mem 1GiB --repeat 1 --seed 42
#
# Inside such a container, exceeding 1 GB is an OOM kill, not a soft slowdown —
# so a completed run genuinely demonstrates the flat-memory claim.

FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
# Build with VCS info stripped-in; -trimpath for reproducibility.
RUN CGO_ENABLED=0 go build -trimpath -o /out/abaco .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/abaco /usr/local/bin/abaco
ENTRYPOINT ["/usr/local/bin/abaco"]
CMD ["--help"]
