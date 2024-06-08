.PHONY: build test run watch serve format check-format code-gen copy

nix-sources := $(shell fd --no-ignore-parent -enix --exclude='spago*')
js-sources := $(shell fd --no-ignore-parent -ejs -ecjs)

esbuild-cmd := "esbuild \
			./output/Main/index.js \
			--bundle \
			--outfile=demo/src/purs.js \
			--platform=browser \
			--format=esm \
			--external:@emurgo/cardano-serialization-lib-browser"

build:
	spago build

test:
	spago test

run:
	spago build --then ${esbuild-cmd}

watch:
	spago build --then ${esbuild-cmd} --watch

serve: run
	(cd demo && npm run build && npm run serve)

format:
	@purs-tidy format-in-place "src/**/*.purs"
	@purs-tidy format-in-place "test/**/*.purs"
	@nixpkgs-fmt ${nix-sources}
	@prettier -w ${js-sources}
	@make check-format

check-format:
	@purs-tidy check "src/**/*.purs"
	@purs-tidy check "test/**/*.purs"
	@nixpkgs-fmt --check ${nix-sources}
	@prettier --log-level warn -c ${js-sources}
	@eslint --quiet ${js-sources} --parser-options 'sourceType: module'

code-gen:
	cd code-gen/parse-csl && make run

copy:
	cp code-gen/parse-csl/output/Lib.js src/Cardano/Serialization/Lib.js
	cp code-gen/parse-csl/output/Lib.purs src/Cardano/Serialization/Lib.purs
	cp code-gen/parse-csl/output/Lib/Internal.purs src/Cardano/Serialization/Lib/Internal.purs
	cp code-gen/parse-csl/output/Lib/Internal.js src/Cardano/Serialization/Lib/Internal.js
