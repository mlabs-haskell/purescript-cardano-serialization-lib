.PHONY: build run

build:
	stack build

run:
	mkdir -p output
	stack run -- output

update:
	cp output/Lib/Internal.js ../../src/Cardano/Serialization/Lib/Internal.js
	cp output/Lib/Internal.purs ../../src/Cardano/Serialization/Lib/Internal.purs
	cp output/Lib.js  ../../src/Cardano/Serialization/Lib.js
	cp output/Lib.purs  ../../src/Cardano/Serialization/Lib.purs
