all:
	gcc bench.c -o bench -static -m32

test:
	py.test --benchmark-only test_*.py
