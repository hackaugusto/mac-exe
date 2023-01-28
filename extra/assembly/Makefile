hello: hello.s
	xcrun as $^
	xcrun ld -lSystem -syslibroot `xcrun -sdk macosx --show-sdk-path` -e _start a.out -o $@

minimal: minimal.s
	xcrun as $^
	xcrun ld -lSystem -syslibroot `xcrun -sdk macosx --show-sdk-path` -e _start a.out -o $@
