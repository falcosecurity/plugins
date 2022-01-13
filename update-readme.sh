#!/bin/bash

cat ./registry/readme_template.md > README.md
python ./registry/docgen.py ./registry/registry.yaml >> README.md