# MPV-2 C++ 构建（无外部依赖，仅需 g++ >= 11 与 make）
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Iinclude

BUILD := build
SRC_CORE := src/blake2b.cpp src/mpv2.cpp
SRC_NET  := src/controller.cpp src/topo.cpp
HDRS := include/blake2b.h include/mpv2.h include/controller.h include/topo.h
BINS := tests vswitch verify_reports bench e2e dashboard exp

.PHONY: all test bench e2e demo clean

all: $(addprefix $(BUILD)/,$(BINS))

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/tests: tests/test_mpv2.cpp $(SRC_CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_CORE) $(SRC_NET) -pthread

$(BUILD)/vswitch: src/vswitch.cpp $(SRC_CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_CORE)

$(BUILD)/verify_reports: src/verify_reports.cpp $(SRC_CORE) src/controller.cpp $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_CORE) src/controller.cpp

$(BUILD)/bench: src/bench.cpp $(SRC_CORE) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_CORE)

$(BUILD)/e2e: src/e2e.cpp $(SRC_CORE) $(SRC_NET) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_CORE) $(SRC_NET)

$(BUILD)/dashboard: src/dashboard.cpp $(SRC_CORE) $(SRC_NET) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_CORE) $(SRC_NET) -pthread

$(BUILD)/exp: src/exp.cpp $(SRC_CORE) $(SRC_NET) $(HDRS) | $(BUILD)
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_CORE) $(SRC_NET)

test: $(BUILD)/tests
	./$(BUILD)/tests tests/golden_vectors.txt

bench: $(BUILD)/bench
	./$(BUILD)/bench

e2e: all
	sudo ./$(BUILD)/e2e

demo: all
	sudo ./$(BUILD)/dashboard --port 8080

exp: all
	sudo ./$(BUILD)/exp

clean:
	rm -rf $(BUILD)
