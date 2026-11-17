.PHONY: install run attack attack-correct test all
PY ?= python3

install:
	$(PY) -m pip install -r requirements.txt

run:
	$(PY) -m src.run

attack:
	$(PY) -m attack.attack --build flawed

attack-correct:
	-$(PY) -m attack.attack --build correct

test:
	$(PY) -m pytest -v

all: run attack attack-correct test
