# Thin wrappers over go, plus the targets that regenerate what the README shows.
GO ?= go
SPICEDB_IMAGE ?= authzed/spicedb:v1.56.2
SPICEDB_PORT ?= 8443

.PHONY: build test hunt mutants check spicedb spicedb-cache-bug demo clean

build:
	$(GO) build -o authz-proof ./cmd/authz-proof

test:
	$(GO) vet ./...
	$(GO) test ./...

# The engine against the reference evaluator on 20,000 random models, and
# every deliberate bug caught.
hunt: build
	./authz-proof hunt --seeds 20000

mutants: build
	./authz-proof mutants --seeds 500

check: test hunt mutants

# Cross-check against a real SpiceDB (Docker). Its dispatch cache is off:
# with it on, SpiceDB's answers depend on the order of questions (see
# `make spicedb-cache-bug`).
spicedb: build
	docker run -d --rm --init --name authz-proof-spicedb -p 127.0.0.1:$(SPICEDB_PORT):8443 $(SPICEDB_IMAGE) \
	  serve --grpc-preshared-key testkey --datastore-engine memory --http-enabled --dispatch-cache-enabled=false
	sleep 5
	./authz-proof crosscheck --endpoint http://127.0.0.1:$(SPICEDB_PORT) --key testkey --random 300 \
	  examples/drive/schema.zed examples/drive/relationships.txt \
	  examples/drive/schema-refactor.zed examples/drive/relationships.txt \
	  examples/drive/schema-reordered.zed examples/drive/relationships.txt \
	  examples/drive/schema-no-parens.zed examples/drive/relationships.txt; \
	  status=$$?; docker stop authz-proof-spicedb > /dev/null; exit $$status

# The order-dependent answer, on a fresh SpiceDB with default settings.
spicedb-cache-bug:
	docker run -d --rm --init --name authz-proof-spicedb-cache -p 127.0.0.1:$(SPICEDB_PORT):8443 $(SPICEDB_IMAGE) \
	  serve --grpc-preshared-key testkey --datastore-engine memory --http-enabled
	sleep 5
	SPICEDB=http://127.0.0.1:$(SPICEDB_PORT) KEY=testkey examples/spicedb-cache/repro.sh; \
	  status=$$?; docker stop authz-proof-spicedb-cache > /dev/null; exit $$status

# Re-record docs/demo.gif from the real CLI. Needs Docker (VHS); the binary
# is static, so it runs in that image.
demo:
	CGO_ENABLED=0 $(GO) build -o authz-proof ./cmd/authz-proof
	docker run --rm -u $$(id -u):$$(id -g) -e HOME=/tmp -v $(CURDIR):/vhs \
	  -v $(CURDIR):/opt/authz-proof:ro ghcr.io/charmbracelet/vhs:v0.10.0 docs/demo.tape

clean:
	rm -f authz-proof
