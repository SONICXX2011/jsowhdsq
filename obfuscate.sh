#!/bin/bash
set -e

npx --yes javascript-obfuscator agent/final.js \
  --output agent/final.obf.js \
  --compact true \
  --string-array true \
  --string-array-encoding rc4 \
  --string-array-threshold 0.75 \
  --string-array-wrappers-count 3 \
  --control-flow-flattening true \
  --control-flow-flattening-threshold 0.75 \
  --dead-code-injection true \
  --dead-code-injection-threshold 0.4 \
  --self-defending false \
  --identifier-names-generator hexadecimal \
  --transform-object-keys true \
  --split-strings true \
  --split-strings-chunk-length 5

echo "Obfuscated:"
ls -la agent/final.obf.js