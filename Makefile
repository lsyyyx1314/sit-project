# SIT 项目顶层入口（100% C++ 实现）
#
#   make          编译全部可执行文件
#   make test     黄金向量交叉校验 + 功能/对抗断言
#   make bench    攻击矩阵与性能基准
#   make e2e      端到端验证（4 台软件交换机，需 root）
#   make deps     安装构建依赖（g++ / make / iproute2）

CPP := cpp

.PHONY: all test bench e2e deps clean

all:
	$(MAKE) -C $(CPP) all

test:
	$(MAKE) -C $(CPP) test

bench:
	$(MAKE) -C $(CPP) bench

e2e:
	$(MAKE) -C $(CPP) e2e

deps:
	@command -v g++ >/dev/null 2>&1 || { \
	  echo "[deps] 安装 g++ / make / iproute2"; \
	  sudo apt-get update -y && \
	  sudo apt-get install -y --no-install-recommends g++ make binutils iproute2; }
	@echo "[deps] g++ : $$(g++ --version | head -1)"
	@echo "[deps] make: $$(make --version | head -1)"

clean:
	$(MAKE) -C $(CPP) clean
	rm -rf dist
