.PHONY: all install run test demo loc docker-build docker-run clean

PYTHON ?= python

all: test

install:
	$(PYTHON) -m pip install -e .

run:
	$(PYTHON) main.py --host 127.0.0.1 --port 8080

test:
	$(PYTHON) -m unittest discover tests

demo:
	$(PYTHON) scripts/run_demo.py

loc:
	$(PYTHON) scripts/loc_counter.py

docker-build:
	docker build -t netsphere:latest .

docker-run:
	docker run -d -p 8080:8080 -p 8081:8081 --name netsphere-app netsphere:latest

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf build dist *.egg-info .pytest_cache 2>/dev/null || true
