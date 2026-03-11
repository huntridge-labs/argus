# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [0.4.3](https://github.com/huntridge-labs/argus/compare/0.4.2...0.4.3) (2026-03-11)

### Dependencies

* **deps:** bump eFAILution/AICaC from 0.1.1 to 0.3.0 ([#36](https://github.com/huntridge-labs/argus/issues/36)) ([b4542bc](https://github.com/huntridge-labs/argus/commit/b4542bc47e8a08ae4f883705cbcb21a6621de414))
* **deps:** bump the github-actions-major group with 3 updates ([a00113d](https://github.com/huntridge-labs/argus/commit/a00113dd2770ed127a7d407e93856ff96f4e38de))


## [0.4.2](https://github.com/huntridge-labs/argus/compare/0.4.1...0.4.2) (2026-03-05)

### Bug Fixes

* **ci:** add packages:read permission for nested reusable workflow jobs ([f4494d7](https://github.com/huntridge-labs/argus/commit/f4494d7313677728f87f90d6fdb2c947d1765c80))

### Tests

* **ci:** add reusable workflow PR testing ([c181cb8](https://github.com/huntridge-labs/argus/commit/c181cb8e2167f20a287d13a9c652780cc64c7baa)), closes [#15](https://github.com/huntridge-labs/argus/issues/15)

## [0.4.1](https://github.com/huntridge-labs/argus/compare/0.4.0...0.4.1) (2026-03-04)

### Bug Fixes

* **scanner-container:** detect and report scan failures instead of silent pass ([86fde1b](https://github.com/huntridge-labs/argus/commit/86fde1b6558fa35636ad3dbdbca2b9e68343bedd)), closes [#18](https://github.com/huntridge-labs/argus/issues/18)
* **scanner-container:** replace raw error dump with concise status and job log link ([7195a5a](https://github.com/huntridge-labs/argus/commit/7195a5ac94ed10969ff0b1e9d3aef4bb56b943d1)), closes [#18](https://github.com/huntridge-labs/argus/issues/18)
* **scanner-container:** use python json.dumps for marker files and add text-based fallback ([15afce0](https://github.com/huntridge-labs/argus/commit/15afce08b19d695bf8a96c9e697ab90c29c9de62))
* **security-summary:** include CodeQL language-suffixed summaries in PR comment ([4b36097](https://github.com/huntridge-labs/argus/commit/4b36097f10b9838754a91bbe7f45210e3981fdee)), closes [#15](https://github.com/huntridge-labs/argus/issues/15)
* **workflows:** resolve all shellcheck findings across CI workflows ([e61d47a](https://github.com/huntridge-labs/argus/commit/e61d47ad74e3515282c66caf75266232eac13a86))

### Code Refactoring

* **scanner-container:** simplify error detection and CVE collection ([6a3c18e](https://github.com/huntridge-labs/argus/commit/6a3c18ecf9c37908995e5e1ec0bc541458a4a1d4))

### Continuous Integration

* **workflows:** add linting for GitHub Actions workflows ([6249813](https://github.com/huntridge-labs/argus/commit/6249813f119892d48b00129fcbfd7f6b3db715b6))

## [0.4.0](https://github.com/huntridge-labs/argus/compare/0.3.0...0.4.0) (2026-02-26)

### Features

* **scn-detector:** expand FedRAMP Low profile for NIST SP 800-53 Rev 5 and FedRAMP 20X ([7e88f98](https://github.com/huntridge-labs/argus/commit/7e88f9876561d3abea8da95ac4d77c3fcfad1d77))

### Code Refactoring

* **deps:** remove Docker package ecosystem configuration from Dependabot ([d4023e9](https://github.com/huntridge-labs/argus/commit/d4023e9b8b1b52c896e4415dfc00045ad430c202))

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
