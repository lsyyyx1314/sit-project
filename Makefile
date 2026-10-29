# SIT 常用目标
PY := .venv/bin/python

.PHONY: help provision test r1 bench attack scheme e2e sync all clean

help:
	@echo "make provision  安装系统与 Python 依赖（Ubuntu 24.04）"
	@echo "make test       运行单元测试"
	@echo "make r1         R1 反例取证（申报书式(5)(6) 恒真退化）"
	@echo "make bench      BPMV 基准（头长/检出率/时延）"
	@echo "make attack     三方攻击矩阵"
	@echo "make scheme      MPV-2 性能基准"
	@echo "make e2e        端到端验证（需 root，Mininet 4 交换机）"
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

attack:
	$(PY) -m sim.attack_matrix --json

scheme:
	$(PY) -m sim.bench_scheme --json

e2e:
	sudo $(PY) -m exp.e2e_verify

all: test r1 bench

sync:
	tar -czf - mpv sim tests scripts exp requirements.txt pytest.ini | bash tools/vm/sshrun.sh "cd ~/SIT && tar xzf -"

clean:
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache
