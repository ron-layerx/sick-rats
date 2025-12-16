.PHONY: clean download scan scan-bucket scan-filesystem unzip all

COUNT ?= 100

clean:
	@bash scripts/clean.sh

download:
	@bash scripts/download.sh $(COUNT)

scan-bucket:
	@bash scripts/scan.sh bucket

scan-filesystem:
	@bash scripts/scan.sh filesystem

unzip:
	@bash scripts/unzip.sh
