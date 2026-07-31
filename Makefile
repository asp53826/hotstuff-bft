.PHONY: test threshold mutation quick clean

test:
	uv run pytest -q

quick:
	uv run pytest -q -m "not slow"

threshold:
	uv run python scripts/threshold_study.py

mutation:
	uv run python scripts/mutation_report.py

clean:
	rm -rf .pytest_cache **/__pycache__ *.egg-info
