.PHONY: build test stand-test clean

build:
	$(MAKE) -C filter

test:
	$(MAKE) -C filter test
	PYTHONPATH=common:logd:cli:authd:integrityd python3 -m unittest discover -s tests/unit -t tests/unit -p "test_*.py" -v

stand-test:
	python3 tests/stand/test_filter_stand.py

clean:
	$(MAKE) -C filter clean
