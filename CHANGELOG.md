# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [0.7.1](https://github.com/huntridge-labs/argus/compare/0.7.0...0.7.1) (2026-04-17)

### Bug Fixes

* add python-slugify ([72f203e](https://github.com/huntridge-labs/argus/commit/72f203e3bcbe50929d2d71aa5a11b140177589dc))
* add python-slugify dep and CLI tests for coverage ([74583cb](https://github.com/huntridge-labs/argus/commit/74583cbf5a9fb7e259ea63f7814f7b3651524d8f))
* **ci:** restore git push credentials for docs deployment ([2ff8593](https://github.com/huntridge-labs/argus/commit/2ff859310a1d96d01aad4a040b8e0aeb55616725))
* **container-scan:** sanitize container names with python-slugify ([98b44c9](https://github.com/huntridge-labs/argus/commit/98b44c9ff478a60b95b0f7d7160aebfa55c8e7ae))

## [Unreleased]

### Bug Fixes

* **container-scan:** sanitize container names with python-slugify to handle problematic directory names (`.devcontainer`, special chars, unicode)

## [0.7.0](https://github.com/huntridge-labs/argus/compare/0.6.8...0.7.0) (2026-04-10)

### Features

* **scanner-supply-chain:** add GitHub Actions workflow security scanner ([253f128](https://github.com/huntridge-labs/argus/commit/253f12807a37f87b86d9470186847f8acdb33e11))
* **scanner-supply-chain:** integrate supply chain scanner into reusable workflow ([acd6996](https://github.com/huntridge-labs/argus/commit/acd69966f7d8b3ddf375ea65c3725ee6958a867f))
* **skills:** add GHES and local act guidance ([f69ab65](https://github.com/huntridge-labs/argus/commit/f69ab6572e726b2835f65e84cb3189953b2cf176))
* **skills:** add local Argus scanner selection skill ([a74d7a8](https://github.com/huntridge-labs/argus/commit/a74d7a8fb3e4d34fda18adfc9cdd569939dff615))

### Bug Fixes

* **ci:** restore git push credentials for release workflow ([8ceb5d6](https://github.com/huntridge-labs/argus/commit/8ceb5d63839aedd0d6dd1eb4172eccb0058a40b6))
* **security:** remediate HIGH supply chain findings from zizmor scan ([#85](https://github.com/huntridge-labs/argus/issues/85)) ([8faab89](https://github.com/huntridge-labs/argus/commit/8faab89fcb5b29cf09c287ad668fb156894438ce))
* **security:** remediate MEDIUM/LOW supply chain findings ([5efdd5d](https://github.com/huntridge-labs/argus/commit/5efdd5db981c8a1aa97046b81ed0a4e86f205b5b))

### Security Tools

* **deps:** bump bridgecrewio/checkov-action ([#81](https://github.com/huntridge-labs/argus/issues/81)) ([4af34c9](https://github.com/huntridge-labs/argus/commit/4af34c98009340663700d7e44c32e08b51a0d2ab))

### Dependencies

* **deps:** bump docker/login-action in /.github/actions/scanner-zap ([#79](https://github.com/huntridge-labs/argus/issues/79)) ([b5db6ee](https://github.com/huntridge-labs/argus/commit/b5db6eecac8d45904eca6ee0cbec29237430d2de))

### Maintenance

* **scanner-supply-chain:** escape actionlint format template for GitHub Actions ([f6fb3a8](https://github.com/huntridge-labs/argus/commit/f6fb3a8e3e92107bd2e238769e3b914fea20c58f))


### Documentation

* **ai:** add release git push credential error pattern ([d7ad5e7](https://github.com/huntridge-labs/argus/commit/d7ad5e75fd8743bd05cc2350c702b437ad93259a))

## [0.6.8](https://github.com/huntridge-labs/argus/compare/0.6.7...0.6.8) (2026-04-02)

### Documentation

* **readme:** update banner and add link to site ([#62](https://github.com/huntridge-labs/argus/issues/62)) ([f8e1d5f](https://github.com/huntridge-labs/argus/commit/f8e1d5f4789e34322c80b1305985458f201fc40e))

## [0.6.7](https://github.com/huntridge-labs/argus/compare/0.6.6...0.6.7) (2026-03-31)

### Security Tools

* **deps:** bump bridgecrewio/checkov-action ([#69](https://github.com/huntridge-labs/argus/issues/69)) ([82abbf0](https://github.com/huntridge-labs/argus/commit/82abbf0aa86db6ea3864566de2f0d75881e65c0c))
* **deps:** bump github/codeql-action ([#67](https://github.com/huntridge-labs/argus/issues/67)) ([912db1d](https://github.com/huntridge-labs/argus/commit/912db1d51ec217e79d4654c321b69a2c2eed074b))
* **deps:** bump github/codeql-action ([#68](https://github.com/huntridge-labs/argus/issues/68)) ([86fb109](https://github.com/huntridge-labs/argus/commit/86fb109a7d5ad31850e6f418c2d8ae83e180c564))
* **deps:** bump github/codeql-action ([#70](https://github.com/huntridge-labs/argus/issues/70)) ([5faa480](https://github.com/huntridge-labs/argus/commit/5faa4808971b437169d4a174146ae13bebb7838c))
* **deps:** bump github/codeql-action ([#71](https://github.com/huntridge-labs/argus/issues/71)) ([36b607e](https://github.com/huntridge-labs/argus/commit/36b607e4de5bc53c611ba35b81e7d2846a9b3663))
* **deps:** bump github/codeql-action ([#72](https://github.com/huntridge-labs/argus/issues/72)) ([f0cba4a](https://github.com/huntridge-labs/argus/commit/f0cba4a5511647a89b121b654bf9ec0fe02c6fa2))
* **deps:** bump github/codeql-action ([#73](https://github.com/huntridge-labs/argus/issues/73)) ([a955f66](https://github.com/huntridge-labs/argus/commit/a955f663ee021497130b0daaa66b68af09fe1d31))
* **deps:** bump github/codeql-action ([#76](https://github.com/huntridge-labs/argus/issues/76)) ([58e050a](https://github.com/huntridge-labs/argus/commit/58e050ad443568801f34c92bcef9d29c81d0e892))
* **deps:** bump github/codeql-action in /.github/actions/scanner-osv ([#75](https://github.com/huntridge-labs/argus/issues/75)) ([573ef18](https://github.com/huntridge-labs/argus/commit/573ef1876a3b61ed3df4a66818bbbea4a303bc5e))

### Dependencies

* **deps:** bump @j-ulrich/release-it-regex-bumper from 5.3.1 to 5.4.0 ([#64](https://github.com/huntridge-labs/argus/issues/64)) ([5120640](https://github.com/huntridge-labs/argus/commit/5120640cf0845af59561b1e5596629e588fbf668))
* **deps:** bump conventional-changelog-conventionalcommits ([#65](https://github.com/huntridge-labs/argus/issues/65)) ([3c98b18](https://github.com/huntridge-labs/argus/commit/3c98b1809a63505ec3b32a4406ba0a2dad4bab42))
* **deps:** bump google/osv-scanner-action ([#74](https://github.com/huntridge-labs/argus/issues/74)) ([b3ffb9c](https://github.com/huntridge-labs/argus/commit/b3ffb9c9837be81a2da90f0b53ca41ca66e4c30d))
* **deps:** bump the github-actions-major group across 1 directory with 2 updates ([#66](https://github.com/huntridge-labs/argus/issues/66)) ([ac15423](https://github.com/huntridge-labs/argus/commit/ac1542389a216e5a2063f8a07975880f14168c96))


## [0.6.6](https://github.com/huntridge-labs/argus/compare/0.6.5...0.6.6) (2026-03-30)

### Bug Fixes

* **ai-summary:** resolve run ID via head SHA lookup ([#61](https://github.com/huntridge-labs/argus/issues/61)) ([b5f4d45](https://github.com/huntridge-labs/argus/commit/b5f4d459948cb7478111385081768f34aa382e98))

## [0.6.5](https://github.com/huntridge-labs/argus/compare/0.6.4...0.6.5) (2026-03-25)

### Bug Fixes

* **ai-summary:** resolve gh api --arg flag error in run lookup ([d395621](https://github.com/huntridge-labs/argus/commit/d395621b8c4ee613221973e178e76b3158f60782))

## [0.6.4](https://github.com/huntridge-labs/argus/compare/0.6.3...0.6.4) (2026-03-22)

### Continuous Integration

* pin all external GitHub Actions to commit SHAs ([8bb7a67](https://github.com/huntridge-labs/argus/commit/8bb7a67815d9ded5921b4eca49f6dcd1aeffebcf))

## [0.6.3](https://github.com/huntridge-labs/argus/compare/0.6.2...0.6.3) (2026-03-21)

### Documentation

* fix incorrect workflow references and broken example links ([7e7b40e](https://github.com/huntridge-labs/argus/commit/7e7b40edb390a7321ed5897df49bf201ca566159))

## [0.6.2](https://github.com/huntridge-labs/argus/compare/0.6.1...0.6.2) (2026-03-21)

### Security Tools

* **deps:** bump anchore/sbom-action ([#51](https://github.com/huntridge-labs/argus/issues/51)) ([3d7b538](https://github.com/huntridge-labs/argus/commit/3d7b5380278dff28bb8f23202d01535e99eae626))
* **deps:** bump anchore/sbom-action in /.github/actions/scanner-syft ([#53](https://github.com/huntridge-labs/argus/issues/53)) ([c0b1a12](https://github.com/huntridge-labs/argus/commit/c0b1a12ab7bcfb347e679fb2c4f83571b1731155))
* **deps:** bump aquasecurity/setup-trivy ([#54](https://github.com/huntridge-labs/argus/issues/54)) ([0a5d093](https://github.com/huntridge-labs/argus/commit/0a5d09363a236603a24c6ae0b29c594314882b96))
* **deps:** bump aquasecurity/trivy-action ([#52](https://github.com/huntridge-labs/argus/issues/52)) ([539da06](https://github.com/huntridge-labs/argus/commit/539da06d41d6823ddca6f94fdb410ac8cc8c7a5e))
* **deps:** bump bridgecrewio/checkov-action ([#50](https://github.com/huntridge-labs/argus/issues/50)) ([6cc7c88](https://github.com/huntridge-labs/argus/commit/6cc7c88701e8b32f77c0eafa8bbe43877c9d41bd))

### Dependencies

* **deps:** bump the github-actions-major group across 27 directories with 9 updates ([d868a7d](https://github.com/huntridge-labs/argus/commit/d868a7d5eda009159c0df72b961da3b590e48ec2))


### Continuous Integration

* **deps:** update dependabot configuration to support multiple directories for GitHub Actions ([91a89cb](https://github.com/huntridge-labs/argus/commit/91a89cb99c50cab0a7d7918da22f9f3c9b2a9b15))

## [0.6.1](https://github.com/huntridge-labs/argus/compare/0.6.0...0.6.1) (2026-03-16)

### Bug Fixes

* **docs:** run mike from repo root where .git exists ([cc4155d](https://github.com/huntridge-labs/argus/commit/cc4155d247f6876ced409f55907d64a214f4f3bf))

## [0.6.0](https://github.com/huntridge-labs/argus/compare/0.5.0...0.6.0) (2026-03-16)

### Features

* **ai-summary:** add AI-powered executive security summary action ([aa9e3da](https://github.com/huntridge-labs/argus/commit/aa9e3da641e90cb10ff6580421ae62db0d414139))

### Bug Fixes

* **ai-summary:** address PR review comments ([88321c4](https://github.com/huntridge-labs/argus/commit/88321c42a4ca964ee816d0472494ff596f19c293))
* **release:** add release-it-ignore inline marker for version ref checker ([0c31410](https://github.com/huntridge-labs/argus/commit/0c314106e991761add3b8e585f5b6da721743b44))

### Dependencies

* **deps:** bump @commitlint/cli from 20.4.3 to 20.5.0 ([#41](https://github.com/huntridge-labs/argus/issues/41)) ([fac7497](https://github.com/huntridge-labs/argus/commit/fac749714d6dca5d043dc1eab637d0c481fe40c1))
* **deps:** bump @commitlint/config-conventional from 20.4.3 to 20.5.0 ([#43](https://github.com/huntridge-labs/argus/issues/43)) ([960218b](https://github.com/huntridge-labs/argus/commit/960218bc0c681157fcbd034373db98d2282a6889))
* **deps:** bump @release-it/conventional-changelog ([#42](https://github.com/huntridge-labs/argus/issues/42)) ([64c744f](https://github.com/huntridge-labs/argus/commit/64c744fdf49dbbe63d53acb6d4c4c5acd4744715))
* **deps:** bump actions/download-artifact ([#44](https://github.com/huntridge-labs/argus/issues/44)) ([a9b99b3](https://github.com/huntridge-labs/argus/commit/a9b99b3b64121917384c6c8bc1b3383bffddbe8b))

### Maintenance

* **aicac:** disable TOON migration suggestions ([730744f](https://github.com/huntridge-labs/argus/commit/730744ffdaa4f665a9435042d2a735860ca6e96f))


### Documentation

* add auto-generated MkDocs documentation site ([74504f0](https://github.com/huntridge-labs/argus/commit/74504f0ff5d551ea1d48626e32b3454d378e80d5))
* add versioned docs with mike ([9d976ee](https://github.com/huntridge-labs/argus/commit/9d976ee13b441c354117e03d1d417bb59c25b49c))
* refactor docsite into modular package with dynamic config ([82dc79a](https://github.com/huntridge-labs/argus/commit/82dc79a02a01a77961a56857405150a45a73810c))

### Tests

* **docsite:** add comprehensive tests for docsite package ([715e9f7](https://github.com/huntridge-labs/argus/commit/715e9f7ea623a02eab5c3830d43812ff95a88d82))
* **docsite:** add tests for diagrams and pages modules ([02bf410](https://github.com/huntridge-labs/argus/commit/02bf4100accfef39f2eb7c8d29a77a33393f8778))

## [0.5.0](https://github.com/huntridge-labs/argus/compare/0.4.3...0.5.0) (2026-03-13)

### Features

* **bandit:** add bandit_config_file input for custom configuration ([1d17613](https://github.com/huntridge-labs/argus/commit/1d17613578217d8f63fbc5af444070751ce7d11e))
* **dependencies:** add OSV and dependency-review scanners ([77e6514](https://github.com/huntridge-labs/argus/commit/77e651469d19e254ecf0626eafe8f0e592651623))

### Bug Fixes

* **bandit:** add bandit_config_file passthrough to reusable workflows ([e0317db](https://github.com/huntridge-labs/argus/commit/e0317db7f5d19b7ff53b350d9042a1fd2239b76f))
* **ci:** add issues:write permission to AICaC workflow ([83d694a](https://github.com/huntridge-labs/argus/commit/83d694a4cb2602cafd7d94fb21afdd169d99bbaf))
* **clamav:** add path traversal protection to archive extraction ([45103de](https://github.com/huntridge-labs/argus/commit/45103def0aa8c68f1fb7c9a8f827516c04e2791a))
* **dependencies:** use collapsible details in summaries and add config_file input ([27ffade](https://github.com/huntridge-labs/argus/commit/27ffadeecf6a219868869c4dca69640698ec7e72))
* **osv:** add config_file to exclude vulnerable test fixtures ([e0242a7](https://github.com/huntridge-labs/argus/commit/e0242a706f1cd89b7638efa269a847296ae11204))
* **release-it:** skip release_output.txt in version ref checker ([f12076b](https://github.com/huntridge-labs/argus/commit/f12076beaed3e679caf91a82e1df7288f4a09cce))

### Maintenance

* **release-it:** add version reference coverage checker and consolidate config ([795c09a](https://github.com/huntridge-labs/argus/commit/795c09ae60d795ccc1ba82ec814dc0c41e1af0fc))
* **release-it:** use stdlib Path.glob for version ref coverage checker ([1b32408](https://github.com/huntridge-labs/argus/commit/1b32408d077cbb2352d273ac1cac0b65dde170cb))
* **reusable-security-hardening:** temp use of feature branch for e2e tests ([f5964ee](https://github.com/huntridge-labs/argus/commit/f5964ee423f1c40c53ed772279a9794bc57d8803))
* **scanner-bandit:** temp use feature branch for e2e tests ([2b1bf8f](https://github.com/huntridge-labs/argus/commit/2b1bf8f48c782c1053a55d31d752c4d8d22d2695))


### Styles

* **release-it:** fix shellcheck SC2005 in release-preview workflow ([b33ab55](https://github.com/huntridge-labs/argus/commit/b33ab5513c43b324238c92c57abd3663bc591bf1))

### Code Refactoring

* **scanner-osv:** use official google/osv-scanner-action Docker image ([eee381e](https://github.com/huntridge-labs/argus/commit/eee381e91b65496ca296e90617a764129ab73808))

### Tests

* **dependencies:** boost patch coverage to 98-99% for new scanners ([e7a8448](https://github.com/huntridge-labs/argus/commit/e7a8448c120139e9dd167028d54d26d90b0d42b0))
* **e2e:** add dependency scanner E2E jobs to test-actions.yml ([8a48688](https://github.com/huntridge-labs/argus/commit/8a486883031976a0e6c468656fd6d946f003c659))

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
