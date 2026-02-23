#!/usr/bin/env bash
# Usage:
#   bun run test:llm        → run all language evals
#   bun run test:llm -de    → run German eval only
#   bun run test:llm -fr    → run French eval only

LANG_SUFFIX="${1:-*}"
PATTERN="src/agent/filter.eval${LANG_SUFFIX}.test.ts"

export TEST_LLM=true
exec bun test $PATTERN
