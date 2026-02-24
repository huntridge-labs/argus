# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [0.3.0](https://github.com/huntridge-labs/argus/compare/0.2.2...0.3.0) (2026-02-24)

### Features

* **scn-detector:** Add FedRAMP Significant Change Notification detector ([#4](https://github.com/huntridge-labs/argus/issues/4)) ([d75451f](https://github.com/huntridge-labs/argus/commit/d75451fb40cb42424b8836cbcd9f493ffd7fb497))

### Dependencies

* **deps:** bump @commitlint/cli from 20.4.1 to 20.4.2 ([#12](https://github.com/huntridge-labs/argus/issues/12)) ([6cd8d81](https://github.com/huntridge-labs/argus/commit/6cd8d81ce621f2a7dfb334ceeecf8fba5616c30a))
* **deps:** bump @commitlint/config-conventional from 20.4.1 to 20.4.2 ([#13](https://github.com/huntridge-labs/argus/issues/13)) ([4c7a435](https://github.com/huntridge-labs/argus/commit/4c7a435b8f4219a530811f4fff20f4c478fb268d))


### Code Refactoring

* **schemas:** co-locate JSON schemas with their actions ([419ac12](https://github.com/huntridge-labs/argus/commit/419ac12cb06aff98e14064f1deae16878b924c19))

## [0.2.2](https://github.com/huntridge-labs/argus/compare/0.2.1...0.2.2) (2026-02-17)

### Bug Fixes

* **container-scan-from-config:** actions ref not being updated on new releases ([bb13006](https://github.com/huntridge-labs/argus/commit/bb1300633780e56031bd305b96ac09f089353de6))

## [0.2.1](https://github.com/huntridge-labs/argus/compare/0.2.0...0.2.1) (2026-02-17)

### Documentation

* add permissions reqs in docstrings and example configs ([9d49319](https://github.com/huntridge-labs/argus/commit/9d49319498398f6342e658c5a2c64b6b09223108))
* **readme:** update codecov token ([9efce2c](https://github.com/huntridge-labs/argus/commit/9efce2c71a4e98e3b217a5b24140243c4aa4b7ca))

### Code Refactoring

* migrate config-driven workflows to composite actions and rename to argus ([a32007d](https://github.com/huntridge-labs/argus/commit/a32007ddf224e8d8ac915e112889cd5115d828ce))

### Tests

* **test-actions:** update container images to use Anchore's Syft in workflows ([47084d1](https://github.com/huntridge-labs/argus/commit/47084d18365ff1857635eff578f209e17f2cc883))

## 0.2.0 (2026-02-17)

### Features

* introducing Argus ([b5f2fc7](https://github.com/huntridge-labs/argus/commit/b5f2fc767a192ca5195d8edefd714208d3fec21b))

### Dependencies

* **deps:** bump eFAILution/AICaC from 0.1.0 to 0.1.1 ([#2](https://github.com/huntridge-labs/argus/issues/2)) ([2fb9c05](https://github.com/huntridge-labs/argus/commit/2fb9c053fff10418ac6c9e3afa8ca5a59602535b))
* **deps:** bump the github-actions-major group with 5 updates ([a939b51](https://github.com/huntridge-labs/argus/commit/a939b51f1d26a241038e41c99470945867b628fc))


### Documentation

* update AICaC badge to reflect Comprehensive compliance ([79af287](https://github.com/huntridge-labs/argus/commit/79af28787fca12343cc00cea581a12cbab73a92b))
