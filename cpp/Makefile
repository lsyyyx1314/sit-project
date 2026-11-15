# MPV-2 C++ 构建（无外部依赖，仅需 g++ >= 11 与 make）
#
# M5.18：-O3 -flto（跨 TU 内联折叠模运算与 blake2b 调用链，scan 判定实测 ≈2.6×）
#        + -MMD -MP 自动头文件依赖（此前 HDRS 手工枚举，新增头文件会静默漏编）。
#        正确性门槛：612 黄金向量逐位一致 + 全量断言 + e2e R1–R7（见 docs/优化空间分析报告.md）。
CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O3 -flto -Wall -Wextra -Iinclude
CXXFLAGS += -MMD -MP

BUILD := build
SRC_CORE := src/blake2b.cpp src/mpv2.cpp src/tpool.cpp
SRC_NET  := src/controller.cpp src/topo.cpp
HDRS := include/blake2b.h include/mpv2.h include/controller.h include/topo.h include/tpool.h
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
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_CORE) $(SRC_NET) -pthread

test: $(BUILD)/tests
	./$(BUILD)/tests tests/golden_vectors.txt

bench: $(BUILD)/bench
	./$(BUILD)/bench

e2e: all
	sudo ./$(BUILD)/e2e

demo: all
	sudo ./$(BUILD)/dashboard --port 8080 --bind 0.0.0.0
	@echo "提示：POST 接口需启动时打印的管理令牌（X-MPV-Token 头）；"
	@echo "      不加 --bind 则默认仅本机 127.0.0.1 可达（安全默认）。"

exp: all
	sudo ./$(BUILD)/exp

clean:
	rm -rf $(BUILD)

# 自动生成的头文件依赖（-MMD -MP）：新增头文件改动可正确触发重编
-include $(wildcard $(BUILD)/*.d)
