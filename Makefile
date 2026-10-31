.PHONY: validate check convert help

validate:  ## Regression test: 0 false positives on ML-ops, all exfil caught
	python3 detections/validate.py

check:     ## Lint the canonical Sigma rules (needs sigma-cli)
	sigma check detections/sigma/

convert:   ## Convert Sigma -> Splunk (example; needs sigma-cli + pysigma-backend-splunk)
	sigma convert -t splunk detections/sigma/

help:
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/'
