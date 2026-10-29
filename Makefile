# SIT 项目顶层入口（C++ 实现）
#
#   make            编译全部可执行文件
#   make test       黄金向量交叉校验 + 功能/对抗断言
#   make bench      攻击矩阵与性能基准
#   make e2e        端到端验证（4 台软件交换机，需 root）
#   make sync       同步到虚拟机 ~/SIT

CPP := cpp

.PHONY: all test bench e2e sync clean

all:
	$(MAKE) -C $(CPP) all

test:
	$(MAKE) -C $(CPP) test

bench:
	$(MAKE) -C $(CPP) bench

e2e:
	$(MAKE) -C $(CPP) e2e

sync:
	tar -czf - $(shell git ls-files) | bash tools/vm/sshrun.sh "cd ~/SIT && tar xzf -"

clean:
	$(MAKE) -C $(CPP) clean
	rm -rf dist
