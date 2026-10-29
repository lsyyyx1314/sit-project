# MPV-2 C++ 构建（无外部依赖，仅需 g++ / make）
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Iinclude
LDFLAGS  ?=

BUILD := build
SRC_CORE := src/blake2b.cpp src/mpv2.cpp
HDRS := include/blake2b.h include/mpv2.h

.PHONY: all test clean

all: $(BUILD)/tests $(BUILD)/vswitch $(BUILD)/verify_reports $(BUILD)/bench

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/tests: tests/test_mpv2.cpp $(SRC_CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ tests/test_mpv2.cpp $(SRC_CORE)

$(BUILD)/vswitch: src/vswitch.cpp $(SRC_CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ src/vswitch.cpp $(SRC_CORE)

$(BUILD)/verify_reports: src/verify_reports.cpp $(SRC_CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ src/verify_reports.cpp $(SRC_CORE)

$(BUILD)/bench: src/bench.cpp $(SRC_CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ src/bench.cpp $(SRC_CORE)

test: $(BUILD)/tests
	./$(BUILD)/tests tests/golden_vectors.txt

bench: $(BUILD)/bench
	./$(BUILD)/bench

e2e: all
	sudo bash scripts/e2e.sh

clean:
	rm -rf $(BUILD)
