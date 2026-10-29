# MPV-2 C++ 构建（无外部依赖，仅需 g++ >= 11 与 make）
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Iinclude

BUILD := build
SRC_CORE := src/blake2b.cpp src/mpv2.cpp
HDRS := include/blake2b.h include/mpv2.h
BINS := tests vswitch verify_reports bench e2e

.PHONY: all test bench e2e clean

all: $(addprefix $(BUILD)/,$(BINS))

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/tests: tests/test_mpv2.cpp $(SRC_CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_CORE)

$(BUILD)/vswitch: src/vswitch.cpp $(SRC_CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_CORE)

$(BUILD)/verify_reports: src/verify_reports.cpp $(SRC_CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_CORE)

$(BUILD)/bench: src/bench.cpp $(SRC_CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_CORE)

$(BUILD)/e2e: src/e2e.cpp $(SRC_CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_CORE)

test: $(BUILD)/tests
	./$(BUILD)/tests tests/golden_vectors.txt

bench: $(BUILD)/bench
	./$(BUILD)/bench

e2e: all
	sudo ./$(BUILD)/e2e

clean:
	rm -rf $(BUILD)
