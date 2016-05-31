all:
	g++ tests.cpp -o tests -static -m32

test:
	py.test --benchmark-only unicorn/bench.py
