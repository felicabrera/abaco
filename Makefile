# ÁBACO — build, test and benchmark targets.
BINARY := abaco
PKG    := ./...

.PHONY: build test vet lint bench bench-ci demo docker-bench clean fmt tidy

build: ## Build the abaco binary.
	go build -o $(BINARY) .

test: ## Run the full test suite (crypto correctness, e2e, determinism).
	go test $(PKG)

test-race: ## Run tests with the race detector.
	go test -race $(PKG)

vet: ## Run go vet.
	go vet $(PKG)

lint: ## Run staticcheck (install: go install honnef.co/go/tools/cmd/staticcheck@latest).
	staticcheck $(PKG)

fmt: ## Format all Go sources.
	gofmt -w .

tidy: ## Tidy the module graph.
	go mod tidy

demo: build ## Run the single-ballot pedagogical walkthrough.
	./$(BINARY) demo --seed 42

bench: build ## Run a representative benchmark and write JSON + CSV.
	./$(BINARY) bench --votes 1000,10000,100000 --repeat 3 --seed 42 \
		--json results.json --csv results.csv

# The two runs the CI workflow performs on every push to main. Kept in sync with
# .github/workflows/benchmark.yml so the tracked series is reproducible locally.
# Run 1 uses --proof-votes none so the O(n) proof phase never contaminates the
# flat-memory pipeline numbers; run 2 is the audit-proof subject.
bench-ci: build ## Reproduce the CI pipeline + proofs runs locally (seed 42).
	./$(BINARY) bench --votes 1000,10000,100000,1000000 --repeat 3 --seed 42 \
		--proof-votes none --json pipeline.json
	./$(BINARY) bench --votes 1000 --proof-votes 1000,10000,100000,1000000 \
		--proof-samples 256 --repeat 3 --seed 42 --json proofs.json

# Hard resource limits via cgroups. This is the defensible way to measure a
# "1 GB / 2 core" machine, since GOMEMLIMIT alone is only a soft target.
docker-bench: ## Build the image and run a memory-capped 1M-vote benchmark.
	docker build -t abaco .
	docker run --rm --memory=1g --cpus=2 abaco \
		bench --votes 1000000 --cores 2 --mem 1GiB --repeat 1 --seed 42

clean: ## Remove build artifacts.
	rm -f $(BINARY) results.json results.csv pipeline.json proofs.json
