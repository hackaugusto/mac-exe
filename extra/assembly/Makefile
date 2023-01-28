hello: a.out
	xcrun ld -lSystem -syslibroot `xcrun -sdk macosx --show-sdk-path` -e _start $^ -o $@

a.out: hello.s
	xcrun as $^
