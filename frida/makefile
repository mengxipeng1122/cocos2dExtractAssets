

all: build_c convert_so
	npx frida-compile agent/index.ts -o _agent.js

clean:
	make -C c clean

convert_so:
	python3 node_modules/ts-frida/dist/bin/so2ts.py --no-content -b c/libs/arm64-v8a/libcocos2dExtractAssets.so -o agent/modinfos/libcocos2dExtractAssets_arm64.ts

build_c:
	make -C c
