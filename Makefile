# SIT 常用目标
PY := .venv/bin/python

.PHONY: help provision test r1 bench sync all clean

help:
	@echo "make provision  安装系统与 Python 依赖（Ubuntu 24.04）"
	@echo "make test       运行单元测试"
	@echo "make r1         R1 反例取证（申报书式(5)(6) 恒真退化）"
	@echo "make bench      BPMV 基准（头长/检出率/时延）"
	@echo "make all        test + r1 + bench"
	@echo "make sync       从本机同步到虚拟机 ~/SIT"

provision:
	bash scripts/provision.sh

test:
	$(PY) -m pytest -q

r1:
	$(PY) -m sim.counterexample_r1 --json

bench:
	$(PY) -m sim.bench_bpmv --json

all: test r1 bench

sync:
	tar -czf - mpv sim tests scripts exp requirements.txt pytest.ini | bash tools/vm/sshrun.sh "cd ~/SIT && tar xzf -"

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache
