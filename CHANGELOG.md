# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [1.5.0](https://github.com/huntridge-labs/argus/compare/1.4.1...1.5.0) (2026-06-15)

### Features

* **scanner-mumps:** support tree-sitter >=0.22 (Language pointer API) ([#249](https://github.com/huntridge-labs/argus/issues/249)) ([80a3dab](https://github.com/huntridge-labs/argus/commit/80a3dab977493d5fb0a4aedfa91a541760d565ec)), closes [#247](https://github.com/huntridge-labs/argus/issues/247)

### Bug Fixes

* **container:** authenticate to private registries via host docker login ([fbb2b15](https://github.com/huntridge-labs/argus/commit/fbb2b15119670695eb326d6bc537b5e02993d483))
* **container:** honor --no-timestamp so the composite action finds results ([568e694](https://github.com/huntridge-labs/argus/commit/568e69486e89f02da769b1a5a439eecee43b154a))
* **scanner-container-summary:** deprecate and forward to security-summary ([#258](https://github.com/huntridge-labs/argus/issues/258)) ([e1fc6fe](https://github.com/huntridge-labs/argus/commit/e1fc6fe133bff636fdc14de7dbb7fadfa566c90e)), closes [#251](https://github.com/huntridge-labs/argus/issues/251)

### Maintenance

* **ai:** migrate .ai/ AICaC context to the v2.0 schema ([#226](https://github.com/huntridge-labs/argus/issues/226)) ([5d62c51](https://github.com/huntridge-labs/argus/commit/5d62c518071e52d36a6f9e42d1a83842f9561186)), closes [#225](https://github.com/huntridge-labs/argus/issues/225) [#227](https://github.com/huntridge-labs/argus/issues/227) [#240](https://github.com/huntridge-labs/argus/issues/240) [#241](https://github.com/huntridge-labs/argus/issues/241) [#228](https://github.com/huntridge-labs/argus/issues/228) [#225](https://github.com/huntridge-labs/argus/issues/225)


### Tests

* **container:** cover host docker-login bridge for grype and syft ([97fc48b](https://github.com/huntridge-labs/argus/commit/97fc48b9b2e3f5407688c644fa07b14852656468))
* **container:** isolate no-creds trivy test from host docker login ([e22239f](https://github.com/huntridge-labs/argus/commit/e22239fa823becb5d2eba030c01a5feadc5bd0ea))

## [1.4.1](https://github.com/huntridge-labs/argus/compare/1.4.0...1.4.1) (2026-06-12)

### Bug Fixes

* **container:** fail fast on unresolved registry_auth credentials ([#255](https://github.com/huntridge-labs/argus/issues/255)) ([e986418](https://github.com/huntridge-labs/argus/commit/e986418b21411a5f7657143550780e602ea581fa)), closes [#253](https://github.com/huntridge-labs/argus/issues/253)
* **release:** single-source promoted image list so all scanners get tagged ([#256](https://github.com/huntridge-labs/argus/issues/256)) ([babd83b](https://github.com/huntridge-labs/argus/commit/babd83b6784fd0f5df4e1085d458c7191f8e7149)), closes [#255](https://github.com/huntridge-labs/argus/issues/255)

### Dependencies

* **deps:** Update github-actions-minor-patch ([#235](https://github.com/huntridge-labs/argus/issues/235)) ([554a53b](https://github.com/huntridge-labs/argus/commit/554a53b8dbc45e449b4fac8033d1914de35ff72f))


## [1.4.0](https://github.com/huntridge-labs/argus/compare/1.3.1...1.4.0) (2026-06-08)

### Features

* **attest:** sign the scan attestation with cosign (OpenVEX in-toto, opt-in) ([#244](https://github.com/huntridge-labs/argus/issues/244)) ([2109310](https://github.com/huntridge-labs/argus/commit/2109310c2d38c7cd36d02237a05a7195d21c7902)), closes [#242](https://github.com/huntridge-labs/argus/issues/242) [#237](https://github.com/huntridge-labs/argus/issues/237) [#240](https://github.com/huntridge-labs/argus/issues/240)
* **container:** bind scan results to the resolved image content digest ([#239](https://github.com/huntridge-labs/argus/issues/239)) ([92668a5](https://github.com/huntridge-labs/argus/commit/92668a584bbec3e03ab051d7db24d25978f0e59e)), closes [#237](https://github.com/huntridge-labs/argus/issues/237)
* **core:** record scanner toolchain provenance in scan results ([#243](https://github.com/huntridge-labs/argus/issues/243)) ([6b39a0f](https://github.com/huntridge-labs/argus/commit/6b39a0f99b472b6ddea9093dbd138aa8e9bce3a6)), closes [#237](https://github.com/huntridge-labs/argus/issues/237) [#241](https://github.com/huntridge-labs/argus/issues/241)
* **reporters:** OpenVEX output for container/SCA scans (spike, [#229](https://github.com/huntridge-labs/argus/issues/229)) ([#230](https://github.com/huntridge-labs/argus/issues/230)) ([b7501e4](https://github.com/huntridge-labs/argus/commit/b7501e488e49074513e0bc9fe6dc3f4bc4bfdadc))
* **reporters:** organize report output by scope (security/lint/supply-chain) ([#231](https://github.com/huntridge-labs/argus/issues/231)) ([988e29d](https://github.com/huntridge-labs/argus/commit/988e29db9a5f5ebdf9ae92b3b9a442a43fb6d09b)), closes [#229](https://github.com/huntridge-labs/argus/issues/229)
* **scanner-mumps:** MUMPS / M language SAST scanner (16 rules, call-graph foundation) ([#213](https://github.com/huntridge-labs/argus/issues/213)) ([bc2e939](https://github.com/huntridge-labs/argus/commit/bc2e939b2cda92c8839feb842582bae3735420ed))

### Bug Fixes

* **container:** scan daemon-present images by ref via docker: source ([#233](https://github.com/huntridge-labs/argus/issues/233)) ([#234](https://github.com/huntridge-labs/argus/issues/234)) ([5305b7a](https://github.com/huntridge-labs/argus/commit/5305b7a0ec825395715a66f2f93406a721ba6911))

### Dependencies

* **deps:** bump node ([#246](https://github.com/huntridge-labs/argus/issues/246)) ([de16ef8](https://github.com/huntridge-labs/argus/commit/de16ef820990b5ed34ecbb2acd421e462b34f821))
* **deps:** bump the npm-minor-patch group with 4 updates ([#245](https://github.com/huntridge-labs/argus/issues/245)) ([9b65035](https://github.com/huntridge-labs/argus/commit/9b65035cf13dff8a0bbdf450ebd726bf5be3ca19))
* **deps:** Update container-images to v1.15.5 ([#236](https://github.com/huntridge-labs/argus/issues/236)) ([a16e887](https://github.com/huntridge-labs/argus/commit/a16e887d6b1be72ece1be16c43806a8cb23c7b6a))
* **deps:** Update container-images to v3.2.531 ([#238](https://github.com/huntridge-labs/argus/issues/238)) ([d6d548f](https://github.com/huntridge-labs/argus/commit/d6d548fc933a7ff851616600fc0e3451de90ef76))


## [1.3.1](https://github.com/huntridge-labs/argus/compare/1.3.0...1.3.1) (2026-06-04)

### Bug Fixes

* **containers:** re-pin promptfoo to immutable version tag ([#232](https://github.com/huntridge-labs/argus/issues/232)) ([47285d3](https://github.com/huntridge-labs/argus/commit/47285d3535e8031c79a5e80e90193f8c4014d48f))

## [1.3.0](https://github.com/huntridge-labs/argus/compare/1.2.1...1.3.0) (2026-06-02)

### Features

* **lint-shell:** add shellcheck linter (closes [#191](https://github.com/huntridge-labs/argus/issues/191)) ([#206](https://github.com/huntridge-labs/argus/issues/206)) ([ca60c2b](https://github.com/huntridge-labs/argus/commit/ca60c2ba80dde85e8fe0f24e1a44be27ed37fba6))
* **scanner-gosec:** add gosec Go SAST scanner ([#207](https://github.com/huntridge-labs/argus/issues/207)) ([17d6f2d](https://github.com/huntridge-labs/argus/commit/17d6f2d192eb0483a0f0ccd091b924976f55a778)), closes [#189](https://github.com/huntridge-labs/argus/issues/189)
* **scanner-kics:** add KICS IaC scanner (closes [#188](https://github.com/huntridge-labs/argus/issues/188)) ([#205](https://github.com/huntridge-labs/argus/issues/205)) ([0d021a0](https://github.com/huntridge-labs/argus/commit/0d021a0e7be5bba080856e6e586a91ea834a7eba))
* **scanner-promptfoo:** add promptfoo LLM-security scanner ([#208](https://github.com/huntridge-labs/argus/issues/208)) ([4185c38](https://github.com/huntridge-labs/argus/commit/4185c385cf553a67298f127e08b6eace31cc4741)), closes [#89](https://github.com/huntridge-labs/argus/issues/89)
* **validate:** add --deep flag for live config validation ([#204](https://github.com/huntridge-labs/argus/issues/204)) ([a23e07e](https://github.com/huntridge-labs/argus/commit/a23e07e31c93fdbac0c3b26d28495a886bb136f3)), closes [186/#187](https://github.com/186/argus/issues/187) [#198](https://github.com/huntridge-labs/argus/issues/198)

### Bug Fixes

* **actions:** v1.2.x reusable-workflow regressions — install argus + invalid needs context ([#211](https://github.com/huntridge-labs/argus/issues/211), [#212](https://github.com/huntridge-labs/argus/issues/212)) ([#214](https://github.com/huntridge-labs/argus/issues/214)) ([09d1771](https://github.com/huntridge-labs/argus/commit/09d177125b26a50256c540727dcba2f0bc30da09))
* **ci:** disable AICaC auto-migrate/regenerate-index unsigned pushes ([#225](https://github.com/huntridge-labs/argus/issues/225)) ([5d95416](https://github.com/huntridge-labs/argus/commit/5d95416d40ecd3f57529609dc1b0d16e61969c36)), closes [#222](https://github.com/huntridge-labs/argus/issues/222)
* **ci:** pin AICaC action back to 0.3.0 (0.6.0 hard-requires .ai/ v2) ([#228](https://github.com/huntridge-labs/argus/issues/228)) ([021c028](https://github.com/huntridge-labs/argus/commit/021c028d951639cd9d407101ce1866e660d61a5d)), closes [#227](https://github.com/huntridge-labs/argus/issues/227) [#222](https://github.com/huntridge-labs/argus/issues/222) [#227](https://github.com/huntridge-labs/argus/issues/227)
* **container:** make smoke fixture world-readable for non-root scanner containers ([#210](https://github.com/huntridge-labs/argus/issues/210)) ([2b57be6](https://github.com/huntridge-labs/argus/commit/2b57be695ec2eeec2d3c3ab18f8ec338361acc23))

### Security Tools

* **deps:** Update dependency opengrep to v1.22.0 ([#216](https://github.com/huntridge-labs/argus/issues/216)) ([5da035c](https://github.com/huntridge-labs/argus/commit/5da035ca61cec634c2d76abcc47012e498cc5109))

### Dependencies

* **deps:** bump node ([#221](https://github.com/huntridge-labs/argus/issues/221)) ([9cbe4ed](https://github.com/huntridge-labs/argus/commit/9cbe4ed0c3eb60ee7d351657e03501eee16fc036))
* **deps:** Update github-actions-major ([#223](https://github.com/huntridge-labs/argus/issues/223)) ([9cab1dd](https://github.com/huntridge-labs/argus/commit/9cab1dd91f62dd39359692c87cfb5224cbc0953c))
* **deps:** Update github-actions-minor-patch ([#222](https://github.com/huntridge-labs/argus/issues/222)) ([0c2fed7](https://github.com/huntridge-labs/argus/commit/0c2fed7fdb28d9113a9738e02668d08feb5c4e73))
* **deps:** Update hashicorp/terraform Docker tag to v1.15.4 ([#215](https://github.com/huntridge-labs/argus/issues/215)) ([171fa0e](https://github.com/huntridge-labs/argus/commit/171fa0ef3ef88fea95a4367ef6a2ab77d84ce682))


### Tests

* **container:** registry-parametrized container-invocation smoke harness + PR gate ([#209](https://github.com/huntridge-labs/argus/issues/209)) ([4a8a9e3](https://github.com/huntridge-labs/argus/commit/4a8a9e30f6fadf9819b3fc6f2049633bd6c74917))

### Continuous Integration

* add Python 3.14 to the test/publish matrix and trove classifiers ([#224](https://github.com/huntridge-labs/argus/issues/224)) ([9085cd6](https://github.com/huntridge-labs/argus/commit/9085cd6fa5292561d7a02a1bbd9ea3d117b0f1bb)), closes [#222](https://github.com/huntridge-labs/argus/issues/222)
* **deps:** move github-actions updates from Dependabot to Renovate ([#220](https://github.com/huntridge-labs/argus/issues/220)) ([1d34ef9](https://github.com/huntridge-labs/argus/commit/1d34ef913eeea7d3ec55d5f4804feb3b346767a1)), closes [#196](https://github.com/huntridge-labs/argus/issues/196) [#11645](https://github.com/huntridge-labs/argus/issues/11645) [#13691](https://github.com/huntridge-labs/argus/issues/13691) [#196](https://github.com/huntridge-labs/argus/issues/196)
* **release:** make the publishing release manual-only (workflow_dispatch) ([#219](https://github.com/huntridge-labs/argus/issues/219)) ([63b875e](https://github.com/huntridge-labs/argus/commit/63b875ea8a1af940158d5aab6345eadcfc03f21a))
* remove obsolete update-pinned-tools workflow + unblock Dependabot github-actions ([#217](https://github.com/huntridge-labs/argus/issues/217), [#196](https://github.com/huntridge-labs/argus/issues/196)) ([#218](https://github.com/huntridge-labs/argus/issues/218)) ([c295dc4](https://github.com/huntridge-labs/argus/commit/c295dc43e76e5eca5815a1334950a75c9153e971)), closes [#216](https://github.com/huntridge-labs/argus/issues/216)

## [1.2.1](https://github.com/huntridge-labs/argus/compare/1.2.0...1.2.1) (2026-05-26)

### Bug Fixes

* **ci:** move renovate config to discoverable path and modernize managers (closes [#195](https://github.com/huntridge-labs/argus/issues/195)) ([#199](https://github.com/huntridge-labs/argus/issues/199)) ([617c386](https://github.com/huntridge-labs/argus/commit/617c38694154f300d2f747c9e14446a566ba47b1))
* **container:** honor execution.registry/registry_map for sub-scanner image pulls (closes [#186](https://github.com/huntridge-labs/argus/issues/186)) ([#187](https://github.com/huntridge-labs/argus/issues/187)) ([6ecbcc3](https://github.com/huntridge-labs/argus/commit/6ecbcc3dae9a493ff2653799ceccd7769df304a8))
* **supply-chain:** treat empty scanner output as zero findings, not parse error ([#185](https://github.com/huntridge-labs/argus/issues/185)) ([f5fd806](https://github.com/huntridge-labs/argus/commit/f5fd806ee99cc1b6c6bcf28db25ad99b80ef633b))

### Security Tools

* **deps:** bump clamav and eslint digests to track upstream republishes ([#198](https://github.com/huntridge-labs/argus/issues/198)) ([7e0a230](https://github.com/huntridge-labs/argus/commit/7e0a230a427cb3786e2cd774e706221b11998469))

### Dependencies

* **deps:** bump the docker-all group across 2 directories with 3 updates ([#194](https://github.com/huntridge-labs/argus/issues/194)) ([a5de592](https://github.com/huntridge-labs/argus/commit/a5de5928a05698876c54ceec4354718729c9c2fc))
* **deps:** Update container-images ([#201](https://github.com/huntridge-labs/argus/issues/201)) ([53fca89](https://github.com/huntridge-labs/argus/commit/53fca89014a2125b3e7e2c7a5452b19334919c60))
* **deps:** Update dependency pyyaml to v6.0.3 ([#202](https://github.com/huntridge-labs/argus/issues/202)) ([9180def](https://github.com/huntridge-labs/argus/commit/9180def0af68705b0857f55e413b282bd1f16957))
* **deps:** Update tool-versions ([#203](https://github.com/huntridge-labs/argus/issues/203)) ([7b6108d](https://github.com/huntridge-labs/argus/commit/7b6108d55c5fdb07ab2916a5241be9c5cc7044a1))

### Maintenance

* **release:** close release-it bumper gaps + bump stale version literals ([#184](https://github.com/huntridge-labs/argus/issues/184)) ([9626515](https://github.com/huntridge-labs/argus/commit/962651581776acf45617feb9ffa46e4957fa314a))


## [1.2.0](https://github.com/huntridge-labs/argus/compare/1.1.0...1.2.0) (2026-05-20)

### Features

* **container:** per-registry credential map for multi-registry auth ([b177c72](https://github.com/huntridge-labs/argus/commit/b177c72dc6833705c323ef2ec2393e9556ecd44c))
* **execution:** per-upstream registry mirrors via registry_map (closes [#178](https://github.com/huntridge-labs/argus/issues/178)) ([#179](https://github.com/huntridge-labs/argus/issues/179)) ([e36c39c](https://github.com/huntridge-labs/argus/commit/e36c39ccbfa2ab8944b11c556f736dd169eb1eba))

### Bug Fixes

* **config:** reject duplicate keys in argus.yml at load time (closes [#177](https://github.com/huntridge-labs/argus/issues/177)) ([#183](https://github.com/huntridge-labs/argus/issues/183)) ([b7ee308](https://github.com/huntridge-labs/argus/commit/b7ee3083b804e990d402326a8e4cd604dc5f1cd2))
* **container:** force Grype registry: source + log redacted cmd argv ([2a0a1d5](https://github.com/huntridge-labs/argus/commit/2a0a1d5feb23f463db70c4ea0231973ef745eee8)), closes [#180](https://github.com/huntridge-labs/argus/issues/180)
* **container:** forward registry credentials to Trivy/Grype/Syft sub-scanners ([f7618da](https://github.com/huntridge-labs/argus/commit/f7618da19cb9bb0782b63e5f3c5afdb26e782d10)), closes [#180](https://github.com/huntridge-labs/argus/issues/180)
* **security:** mitigate dogfood-scan findings (bandit B103/B310, lodash OSV) ([#175](https://github.com/huntridge-labs/argus/issues/175)) ([6c02a84](https://github.com/huntridge-labs/argus/commit/6c02a8444afb9a008ddd2211232b379aa163f44e))
* **update-check:** suppress bogus "1.1.0 → 1.0.1" downgrade notice (closes [#174](https://github.com/huntridge-labs/argus/issues/174)) ([#176](https://github.com/huntridge-labs/argus/issues/176)) ([3c93c52](https://github.com/huntridge-labs/argus/commit/3c93c521a6ef36972e75225b59f6b7f123a8fda7)), closes [#168-N](https://github.com/huntridge-labs/argus/issues/168-N)

### Security Tools

* **deps:** bump clamav digest to track upstream 1.5 republish ([#181](https://github.com/huntridge-labs/argus/issues/181)) ([700f91d](https://github.com/huntridge-labs/argus/commit/700f91d8878b7023ea38b7ba6b33e21cc3aab555))

### Maintenance

* **container:** demote invocation logs from INFO to DEBUG ([7873e38](https://github.com/huntridge-labs/argus/commit/7873e3888ee4022fd9e9e0c954914b732b1413e9))


## [1.1.0](https://github.com/huntridge-labs/argus/compare/1.0.1...1.1.0) (2026-05-17)

### Features

* **core:** PhaseResult + ScanResult.partial_failure for multi-phase scanners ([f0bc4b2](https://github.com/huntridge-labs/argus/commit/f0bc4b27b28ca2762e57d6b92e2d533898b93e0d)), closes [#169](https://github.com/huntridge-labs/argus/issues/169) [#170](https://github.com/huntridge-labs/argus/issues/170) [#169](https://github.com/huntridge-labs/argus/issues/169) [#170](https://github.com/huntridge-labs/argus/issues/170)

### Bug Fixes

* **cache:** distinguish "not cached" from "empty mount" in cache info ([#168](https://github.com/huntridge-labs/argus/issues/168)-M) ([d13e592](https://github.com/huntridge-labs/argus/commit/d13e592fb41f0ab1015e97d659dd7aea79f4ecb6)), closes [#168-M](https://github.com/huntridge-labs/argus/issues/168-M)
* **clamav:** drop clamav from CACHE_MOUNTS, refine cache-info note ([#168](https://github.com/huntridge-labs/argus/issues/168)-N, [#168](https://github.com/huntridge-labs/argus/issues/168)-M) ([180c72c](https://github.com/huntridge-labs/argus/commit/180c72c57817e837b69184ab42262326584e9719)), closes [#168-N](https://github.com/huntridge-labs/argus/issues/168-N) [#168-M](https://github.com/huntridge-labs/argus/issues/168-M)
* **clamav:** redirect freshclam db to /tmp so it can write ([#168](https://github.com/huntridge-labs/argus/issues/168)-N) ([05366bc](https://github.com/huntridge-labs/argus/commit/05366bcbe02627a7ebd8a3707315a7d600a090f7)), closes [#168-N](https://github.com/huntridge-labs/argus/issues/168-N) [#168-M](https://github.com/huntridge-labs/argus/issues/168-M)
* **classify:** exit non-zero when git diff itself fails ([#168](https://github.com/huntridge-labs/argus/issues/168)-J) ([811daa2](https://github.com/huntridge-labs/argus/commit/811daa2962e1942260cdca87a1845ce2b0cda189)), closes [#168-J](https://github.com/huntridge-labs/argus/issues/168-J)
* **cli:** correct surface inconsistencies and silence --quiet (issue [#168](https://github.com/huntridge-labs/argus/issues/168)-D) ([d7408b6](https://github.com/huntridge-labs/argus/commit/d7408b6c6163c06ab3553a48fa93b5c534d3d1d0)), closes [#168-D](https://github.com/huntridge-labs/argus/issues/168-D)
* **collect:** skip per-run timestamp dirs and the latest symlink ([#168](https://github.com/huntridge-labs/argus/issues/168)-L) ([e2aa06b](https://github.com/huntridge-labs/argus/commit/e2aa06bfddc12b130e1fc366e7ed11d3078af708)), closes [#168-L](https://github.com/huntridge-labs/argus/issues/168-L)
* **docsite:** TUI screenshots, nav titles + grouping, orphan pages, regen on bump ([#167](https://github.com/huntridge-labs/argus/issues/167)) ([ce1d580](https://github.com/huntridge-labs/argus/commit/ce1d580dd9609266ddcbb0f3affb3765eeb0fe9e))
* **engine:** cache permanent pull failures so inline retry skips ([#168](https://github.com/huntridge-labs/argus/issues/168)-H followup) ([67e1025](https://github.com/huntridge-labs/argus/commit/67e10253dfddc3931bbf6644e2c45f7bcfd41889)), closes [#168-H](https://github.com/huntridge-labs/argus/issues/168-H)
* **engine:** categorize container-pull failures, skip retry on permanent errors ([2d199ce](https://github.com/huntridge-labs/argus/commit/2d199ce9d7ccd93db95d6d55cb5eb3bfd6953c92))
* **lint-terraform:** per-phase PhaseResult, fail loudly when a phase can't run ([#169](https://github.com/huntridge-labs/argus/issues/169)) ([c2ae9b3](https://github.com/huntridge-labs/argus/commit/c2ae9b3e761b3e6aad2b02235227d0d614b6e959))
* **mcp:** advertise argus version on initialize ([#168](https://github.com/huntridge-labs/argus/issues/168)-O) ([40e6ddd](https://github.com/huntridge-labs/argus/commit/40e6dddfa1a6df396106d745860403df6f212a55)), closes [#168-O](https://github.com/huntridge-labs/argus/issues/168-O)
* **release:** derive schema version from __version__, widen bumper rules for docs ([2719900](https://github.com/huntridge-labs/argus/commit/2719900571ace221ded78290544889712d0fd7e4)), closes [#168-A](https://github.com/huntridge-labs/argus/issues/168-A) [#167-3](https://github.com/huntridge-labs/argus/issues/167-3) [#168](https://github.com/huntridge-labs/argus/issues/168) [#167](https://github.com/huntridge-labs/argus/issues/167)
* **reporters:** de-dup GitLab CC descriptions, JUnit type uses rule id ([#168](https://github.com/huntridge-labs/argus/issues/168)-G) ([b76cbd9](https://github.com/huntridge-labs/argus/commit/b76cbd9d384f155232ba14488791ad14aa9f1281)), closes [#168-G](https://github.com/huntridge-labs/argus/issues/168-G) [#168-G](https://github.com/huntridge-labs/argus/issues/168-G)
* **reporters:** fall back to built-in modules without entry-points ([#172](https://github.com/huntridge-labs/argus/issues/172)) ([5c9cc6b](https://github.com/huntridge-labs/argus/commit/5c9cc6b01acdd9f72e0cf69787356a9c5614fa17))
* **report:** follow argus-results/latest symlink when -r not specified ([#168](https://github.com/huntridge-labs/argus/issues/168)-K) ([d6486de](https://github.com/huntridge-labs/argus/commit/d6486ded82950c9d823aac95095dd984cad7c328)), closes [#168-K](https://github.com/huntridge-labs/argus/issues/168-K)
* **reporting:** emit Info row in markdown + --output-vars, sync validator with registry ([51757d8](https://github.com/huntridge-labs/argus/commit/51757d8bccb8b408eadb91d5450d35f90cb59b2a)), closes [#168-E](https://github.com/huntridge-labs/argus/issues/168-E) [#168-F](https://github.com/huntridge-labs/argus/issues/168-F)
* **scanners:** container surfaces partial-failure when no source configured ([#170](https://github.com/huntridge-labs/argus/issues/170)) ([9605356](https://github.com/huntridge-labs/argus/commit/96053566221c1c72569c0b51548c75b9b23ca0b1)), closes [#169](https://github.com/huntridge-labs/argus/issues/169)
* **scanners:** precondition errors don't trigger fallback dance ([#168](https://github.com/huntridge-labs/argus/issues/168)-I) ([d834c9a](https://github.com/huntridge-labs/argus/commit/d834c9afba4437e97e2931c0211c52be0d756f9b)), closes [#168-I](https://github.com/huntridge-labs/argus/issues/168-I) [#168-I](https://github.com/huntridge-labs/argus/issues/168-I)
* **security:** flip keep_raw default off, exclude argus-results from scans ([92edff5](https://github.com/huntridge-labs/argus/commit/92edff56c4d20640d175f99697e62304875a79f6)), closes [#168](https://github.com/huntridge-labs/argus/issues/168)
* **view:** add --path flag as argparse-safe escape hatch ([#168](https://github.com/huntridge-labs/argus/issues/168)-D5) ([512f954](https://github.com/huntridge-labs/argus/commit/512f95419cff5817cb0cdac8026ffffdf7016f2c)), closes [#168-D5](https://github.com/huntridge-labs/argus/issues/168-D5)

### Dependencies

* **deps:** bump the npm-major group across 1 directory with 4 updates ([bb14329](https://github.com/huntridge-labs/argus/commit/bb14329722de666ecba92b622f2905de844834c0))
* **deps:** bump the pip-all group with 2 updates ([312233b](https://github.com/huntridge-labs/argus/commit/312233bae9a0b17cea4b058299865452f6515115))


### Tests

* cover partial-failure paths in models, reporters, and lint-terraform ([f902e83](https://github.com/huntridge-labs/argus/commit/f902e83c9e05b953a782911a730c0d017277595b)), closes [#173](https://github.com/huntridge-labs/argus/issues/173)

### Continuous Integration

* gate push-main workflows against chore(release): commits ([84bcbd4](https://github.com/huntridge-labs/argus/commit/84bcbd4a74d0dd3f28e44827d67eaf2eccfbf022))

## [1.0.1](https://github.com/huntridge-labs/argus/compare/1.0.0...1.0.1) (2026-05-16)

### Bug Fixes

* **release:** tighten containers.py regex-bumper, repair 1.0.0 corruption ([dae65f0](https://github.com/huntridge-labs/argus/commit/dae65f044b7bfdc97b41b862f50675e48bec23b8))

## [1.0.0](https://github.com/huntridge-labs/argus/compare/0.7.2...1.0.0) (2026-05-16)

### ⚠ BREAKING CHANGES

* **release:** cosign verification command for Argus-owned images
must use --certificate-identity-regexp matching
`.github/workflows/release.yml@` rather than `publish-release.yml@`
for 1.0.0+ images. The argus SDK's built-in verifier is updated in
lock-step. External scripts running cosign verify directly must
update their regex. 0.7.x images remain verifiable with the old
regex.
* **ci:** Remove 22 workflows replaced by argus Python SDK.

Removed 15 scanner-*.yml thin wrappers, 6 compound orchestrators
(reusable-security-hardening, container-scan, dependency-scan,
infrastructure-scan, linting, container-scan-from-config), and
security-reusable-demo.

Refactored test-reusable-workflows.yml into argus SDK integration test.

Removed 5 example workflows that referenced deleted workflows.
Updated all documentation (README, QUICK-START, AGENTS, docs/,
.ai/ files) to position the SDK as primary interface with
composite actions as secondary for GitHub Actions users.

Updated docsite.yml, zizmor.yml, bug report template, and
agent skills to reflect the new architecture.

### Features

* **audit:** defensive redaction pass on log + manifest writes ([#148](https://github.com/huntridge-labs/argus/issues/148)) ([6dc1ba3](https://github.com/huntridge-labs/argus/commit/6dc1ba36428248d1f4d2d73991bcce2911f47519)), closes [#5](https://github.com/huntridge-labs/argus/issues/5)
* **browse:** interactive findings TUI + shared findings_view module ([#96](https://github.com/huntridge-labs/argus/issues/96)) ([1672957](https://github.com/huntridge-labs/argus/commit/1672957f84f818995abf1cabe9289c93fc3b9629))
* **ci:** add dogfood security scan workflow using argus SDK ([48221d0](https://github.com/huntridge-labs/argus/commit/48221d0900655ff54b8170cd12590b17fec8dedc))
* **ci:** add PR comment with aggregated container scan results ([f2c2bdc](https://github.com/huntridge-labs/argus/commit/f2c2bdc1332ad95a184de8a2e7fef53d92a3ad89))
* **ci:** add Python version matrix and version ref check to CI ([7d3eacd](https://github.com/huntridge-labs/argus/commit/7d3eacdaf10c082eb48272c13555bf7186642de4))
* **ci:** enable multi-arch container builds (amd64 + arm64) ([314b2cf](https://github.com/huntridge-labs/argus/commit/314b2cfd6b9211ba1e1db3d6f60d3bdfe3e0294f))
* **ci:** restore all reusable workflows powered by argus CLI ([46bb2f9](https://github.com/huntridge-labs/argus/commit/46bb2f94583564842bdc755dd180c863d11d9b4c))
* **ci:** rich container scan PR comment with severity breakdown ([be3ff25](https://github.com/huntridge-labs/argus/commit/be3ff2535b068b1b7fbb1d5772e2017588edff16))
* **ci:** unique dev versions for TestPyPI publishing ([293b6d7](https://github.com/huntridge-labs/argus/commit/293b6d79d2b0f024f37a2d306bba772585afb545)), closes [#88](https://github.com/huntridge-labs/argus/issues/88)
* **ci:** validate audit trail artifacts in PR pipeline ([df09432](https://github.com/huntridge-labs/argus/commit/df0943228355c41a5b5ec2012deda5cd3cbe2927))
* **ci:** validate built wheel with PR containers in build-containers ([0c6c246](https://github.com/huntridge-labs/argus/commit/0c6c246447713e38140cdc8389059069f2fa7fe2))
* **cli:** --registry-password-stdin and --zap-auth-password-stdin ([#145](https://github.com/huntridge-labs/argus/issues/145)) ([8e51955](https://github.com/huntridge-labs/argus/commit/8e5195528a4f05ee93a7ba4dd980ce895155dc6a)), closes [#2](https://github.com/huntridge-labs/argus/issues/2)
* **cli:** add --output-vars for machine-readable CI output ([68fb7d6](https://github.com/huntridge-labs/argus/commit/68fb7d65f8e67b31ecbdf0d7951b4928617593fd))
* **cli:** add scan spinner and verbose logger handling ([7c14f42](https://github.com/huntridge-labs/argus/commit/7c14f42455097874a15075fb987a91af1bb87cac))
* **cli:** add shell completion scripts and bin/argus entry point ([e183eae](https://github.com/huntridge-labs/argus/commit/e183eae112511316290767771bd369752413fde9))
* **cli:** add shell tab completion via argcomplete ([8e3a8d7](https://github.com/huntridge-labs/argus/commit/8e3a8d78206d003b5d538a0b8258d091cb87b47b))
* **cli:** background update check with pip-style notice ([#124](https://github.com/huntridge-labs/argus/issues/124)) ([3ccf528](https://github.com/huntridge-labs/argus/commit/3ccf52827256c4587a60793ca422548cec0dbc82))
* **cli:** dynamic completion via argus completion subcommand ([9479d17](https://github.com/huntridge-labs/argus/commit/9479d179d4cd1db0e2f7d11f0bcff8421c75093a))
* **cli:** surface missing tools after init and scan ([#92](https://github.com/huntridge-labs/argus/issues/92)) ([0638f8e](https://github.com/huntridge-labs/argus/commit/0638f8ee4107dd2ae81cc334ff6b63f3570fba4c))
* **containers:** mutually exclusive image vs dockerfile, per-target cleanup, IDE schema hint ([#121](https://github.com/huntridge-labs/argus/issues/121)) ([519afe0](https://github.com/huntridge-labs/argus/commit/519afe00ab3fb41ef8cd8024b46f9f26673374a3))
* **deps:** add Renovate config for container images and tool versions ([dfeeb7c](https://github.com/huntridge-labs/argus/commit/dfeeb7ca13d2e6303fa430499f850839dc82af59))
* **docker:** harden containers, add build/scan CI, container-first engine ([483870c](https://github.com/huntridge-labs/argus/commit/483870c3587be3f311c1ebcaacf3eabba911b50c))
* **engine:** add --exclude flag and auto-respect ignore files ([c788fce](https://github.com/huntridge-labs/argus/commit/c788fceb96b2468b7af7f65a2f85080fbd1a0ee6))
* **engine:** add --fail-fast, --timeout, and improved --list ([23912c3](https://github.com/huntridge-labs/argus/commit/23912c35f836d609c700880b0b434cbf46f253ad))
* **engine:** add scanner DB cache volume mounts for container runs ([7059af6](https://github.com/huntridge-labs/argus/commit/7059af6e858fd30d9dd9fb158f421283e8dfb0d6))
* **engine:** image pre-warming + lazy pulls ([#139](https://github.com/huntridge-labs/argus/issues/139)) ([efcce9f](https://github.com/huntridge-labs/argus/commit/efcce9f4ea9cb800eed4444fbe41b9a060c27ace))
* **engine:** parallel scanner execution via thread pool ([18676bb](https://github.com/huntridge-labs/argus/commit/18676bbb3ad2fe7c5fc763848b943a037216cc75))
* **engine:** per-scanner timing in audit trail and performance TODOs ([ead6e1d](https://github.com/huntridge-labs/argus/commit/ead6e1d130bfd5c135be3252c36d2c90cf154556))
* **engine:** support Docker, Podman, and nerdctl container runtimes ([c97e81c](https://github.com/huntridge-labs/argus/commit/c97e81c134bee1b9a63966c831e763ceb7207bfb))
* **engine:** tool version enforcement for supply chain integrity ([5fea42a](https://github.com/huntridge-labs/argus/commit/5fea42aacce4678ad7c29d82af1259a759a662f1))
* MCP tests, SCN schema port, skill refactor, and roadmap cleanup ([0350c3f](https://github.com/huntridge-labs/argus/commit/0350c3fefe4dd267588b80faf2f34c2687ceb9bf))
* **mcp:** add MCP server for AI assistant integration ([8412ec8](https://github.com/huntridge-labs/argus/commit/8412ec893a1caa8c1a0e179c6cc81d59a4ce2071))
* **mcp:** add unified security_review tool and cache freshness signals ([#102](https://github.com/huntridge-labs/argus/issues/102)) ([888a66e](https://github.com/huntridge-labs/argus/commit/888a66e0a6202464ad5d15cf8000543497a2137a))
* **mcp:** mature MCP server with 8 tools, 3 resources, 3 prompts ([d927c82](https://github.com/huntridge-labs/argus/commit/d927c8258f1b0e77be4ea5a88cf5e96bb7959d08))
* **models:** add from_dict() and integration tests for argus report ([21f3dd1](https://github.com/huntridge-labs/argus/commit/21f3dd13c28467ad16cd82020f9504633b9f41e8))
* multi-arch Dockerfiles, auto-detect config, and ARM64 support ([da1e224](https://github.com/huntridge-labs/argus/commit/da1e224f9fc764da458b6183c02645b60e86ec14))
* **preflight:** add CI preflight checks with living issue reporting ([fde3b97](https://github.com/huntridge-labs/argus/commit/fde3b973aa5ed5819a307ea692e211f9b4268a24))
* **pypi:** hardened pyproject.toml, publish workflow, and safety check ([9359b0f](https://github.com/huntridge-labs/argus/commit/9359b0ff3b5dd07b398d49695ce88e34ffd71ed5))
* **redact:** pattern-based second-pass safety net at Finding construction ([#138](https://github.com/huntridge-labs/argus/issues/138)) ([febe4d5](https://github.com/huntridge-labs/argus/commit/febe4d5710dceba534359f0a162eb40cf4283e57))
* **reporters:** add github, gitlab, and junit reporters ([#130](https://github.com/huntridge-labs/argus/issues/130)) ([4826be4](https://github.com/huntridge-labs/argus/commit/4826be4cb8bed319e598f2c6ed365e4774a706d0)), closes [#205](https://github.com/huntridge-labs/argus/issues/205)
* **reporters:** Info column in summary + hook exit propagation ([#158](https://github.com/huntridge-labs/argus/issues/158)) ([1727b87](https://github.com/huntridge-labs/argus/commit/1727b8776e04456824662a84598e1b6f24574ec1))
* **reporters:** plugin registration via Python entry-points ([#140](https://github.com/huntridge-labs/argus/issues/140)) ([5432155](https://github.com/huntridge-labs/argus/commit/54321557049b94af2b7b8c55fb52abcc6b2b9ba5))
* **scan-container:** support config-driven and manifest-file targets ([#112](https://github.com/huntridge-labs/argus/issues/112)) ([f4e39fd](https://github.com/huntridge-labs/argus/commit/f4e39fd2bd8ed1cd4808346649c0280abcc9815a))
* **scan:** accept a directory of SBOMs on --sbom ([6f57629](https://github.com/huntridge-labs/argus/commit/6f57629fd61d97b4c0a05b08b7cf685030231792))
* **scan:** emit canonical argus-results.json + persist raw scanner output (source + container) ([#116](https://github.com/huntridge-labs/argus/issues/116)) ([8d184d6](https://github.com/huntridge-labs/argus/commit/8d184d686172500c92290c3040890793ee00a935)), closes [#111](https://github.com/huntridge-labs/argus/issues/111)
* **scanner-container:** exposed-port surface as new sub-scanner ([#149](https://github.com/huntridge-labs/argus/issues/149)) ([7837c6e](https://github.com/huntridge-labs/argus/commit/7837c6e6f9c37c9a16453bb688d24a080679fba6))
* **scan:** support pre-built SBOM input via --sbom ([#94](https://github.com/huntridge-labs/argus/issues/94)) ([6e02525](https://github.com/huntridge-labs/argus/commit/6e025254b0c4f658ef42b11c0bdd6d00dc5060b2))
* **scn:** port tests to argus/tests/scn/ and thin action wrapper ([572c895](https://github.com/huntridge-labs/argus/commit/572c8950b7f25f77bddba0c11fd43d6ea4fb380e))
* **sdk:** add 6 linter modules — yaml, json, python, javascript, dockerfile, terraform ([7568ae4](https://github.com/huntridge-labs/argus/commit/7568ae4c73de7f47ad5b1d8d111faaa7a87176c2))
* **sdk:** add argus collect command for multi-job log aggregation ([43cdbd4](https://github.com/huntridge-labs/argus/commit/43cdbd4ec6f6ce995b1c7f80ffd6bbe691434c04))
* **sdk:** add argus container subcommand for container image scanning ([635ad1d](https://github.com/huntridge-labs/argus/commit/635ad1d456f1ee64c62d9ffb17d93bb0550fffa4))
* **sdk:** add argus core SDK with models, config, and engine ([3396a06](https://github.com/huntridge-labs/argus/commit/3396a06ec1194b0fbaa28ea5e42025ee6d01fdf7))
* **sdk:** add argus init, JSON schema, and sync skill file ([97ab23c](https://github.com/huntridge-labs/argus/commit/97ab23c9781dd6c50a883324f495e9bc1230b5a6))
* **sdk:** add ASCII art banner to argus init ([1d7dfe0](https://github.com/huntridge-labs/argus/commit/1d7dfe046f51fcfa9cbd698c727a6850dead6779))
* **sdk:** add audit module for structured logging and evidence trail ([3b76e93](https://github.com/huntridge-labs/argus/commit/3b76e93528562bb4089be5c0544680df55eb6e16))
* **sdk:** add comprehensive logging throughout the engine ([2245536](https://github.com/huntridge-labs/argus/commit/2245536271c6e8961662df82007b3b3d4bfac1a8))
* **sdk:** add config schema validation with argus validate command ([0102f3f](https://github.com/huntridge-labs/argus/commit/0102f3fc19c27767b469b098dce54daccc028606))
* **sdk:** add DAST lifecycle with auto port discovery from images ([3ee0123](https://github.com/huntridge-labs/argus/commit/3ee01237f79cad8192d36388bb0a896d7fd181a8))
* **sdk:** add Docker execution backend with container image registry ([c10ec32](https://github.com/huntridge-labs/argus/commit/c10ec325c0addb04f73e0440386580a828250eb2))
* **sdk:** add Dockerfiles and Dependabot config for container images ([fa48d7d](https://github.com/huntridge-labs/argus/commit/fa48d7d39aded787cc78e74a029cbd8a43f288e4))
* **sdk:** add reporters for terminal, markdown, SARIF, and JSON output ([0ac3b7d](https://github.com/huntridge-labs/argus/commit/0ac3b7dadd5204e7d51cbde9c785f77692deb4e3))
* **sdk:** add resource management to container engine ([eb11281](https://github.com/huntridge-labs/argus/commit/eb11281f6d5562cc46b5f3f86a30df7255499cd9))
* **sdk:** add scanner-specific help for argus scan <name> --help ([23630e9](https://github.com/huntridge-labs/argus/commit/23630e9d49a6cf64d2608c8a81c6e30db93ced50))
* **sdk:** fix CLI help UX and add auto-generated CLI docs ([ba4527e](https://github.com/huntridge-labs/argus/commit/ba4527ecb1037fd376b6e488c9a6a19fdc02be3f))
* **sdk:** improve validate with scanner breakdown, --check-tools, and --strict ([b2ac8f7](https://github.com/huntridge-labs/argus/commit/b2ac8f719101dc0acdb79983a158b7b6846f5b8d))
* **sdk:** interactive architecture map — one transformer, three consumers ([#163](https://github.com/huntridge-labs/argus/issues/163)) ([95c5f73](https://github.com/huntridge-labs/argus/commit/95c5f73b4f17bb5b001f23a5f23e307879a6084e)), closes [#arch-data](https://github.com/huntridge-labs/argus/issues/arch-data) [#39](https://github.com/huntridge-labs/argus/issues/39) [#39](https://github.com/huntridge-labs/argus/issues/39)
* **sdk:** log container image SHA256 digests for supply chain forensics ([36ac8b9](https://github.com/huntridge-labs/argus/commit/36ac8b9e2a1f344b3cbe760bb41875b46f935922))
* **sdk:** port all 10 scanner modules to argus SDK ([dbb4dd0](https://github.com/huntridge-labs/argus/commit/dbb4dd0bf5b189e47935f4822f582fdff89369a5))
* **sdk:** port SCN detector to argus classify subcommand ([1370ca5](https://github.com/huntridge-labs/argus/commit/1370ca5366772bbf102e0f9677f73354d0446f0e))
* **sdk:** refactor init banner to external file, add scroll effect and easter egg ([b9e4ac5](https://github.com/huntridge-labs/argus/commit/b9e4ac5003a99447a97897717976053ddecbfcc1))
* **sdk:** remote registry scanning without pulling images ([702de1b](https://github.com/huntridge-labs/argus/commit/702de1b5ec76a8654412168097adfca204991c12))
* **sdk:** thin wrapper PoC, CLI docs gate, and scripts restructure ([b13ce49](https://github.com/huntridge-labs/argus/commit/b13ce49d4abcf91910e6721b971b9222a1c8511f))
* **sdk:** timestamped run directories preserve scan history ([7bdaa9e](https://github.com/huntridge-labs/argus/commit/7bdaa9e69934e57b8e269f88fabb990bfb49f016))
* **sdk:** truecolor ASCII art banner for argus init ([738696c](https://github.com/huntridge-labs/argus/commit/738696c9c7b47251a0a48b46292c2b7b3f337e83))
* **secrets:** credential resolver + zap config-passthrough wiring ([#142](https://github.com/huntridge-labs/argus/issues/142)) ([b2266bf](https://github.com/huntridge-labs/argus/commit/b2266bf03083de5c03f2dff5c9819406dc593b5c))
* **serve:** SDK-hosted localhost web UI — argus serve ([#97](https://github.com/huntridge-labs/argus/issues/97)) ([b030717](https://github.com/huntridge-labs/argus/commit/b0307178323f531b6bb7cb9eeed8ab75f3e2e5b7)), closes [#findings-target](https://github.com/huntridge-labs/argus/issues/findings-target) [#0b0f0d](https://github.com/huntridge-labs/argus/issues/0b0f0d) [#111916](https://github.com/huntridge-labs/argus/issues/111916) [#16211c](https://github.com/huntridge-labs/argus/issues/16211c) [#84b852](https://github.com/huntridge-labs/argus/issues/84b852) [#dbe64c](https://github.com/huntridge-labs/argus/issues/dbe64c) [#eaf2ea](https://github.com/huntridge-labs/argus/issues/eaf2ea) [#9fb09f](https://github.com/huntridge-labs/argus/issues/9fb09f) [#1f2a22](https://github.com/huntridge-labs/argus/issues/1f2a22) [#0b0f0d](https://github.com/huntridge-labs/argus/issues/0b0f0d) [#0b0f0d](https://github.com/huntridge-labs/argus/issues/0b0f0d)
* **supply-chain:** cosign-verify argus images + security policy doc ([#146](https://github.com/huntridge-labs/argus/issues/146)) ([864c162](https://github.com/huntridge-labs/argus/commit/864c1622019e215d4a937eb261865e0d1ab9857f))
* **view-browser:** add /log scan-log viewer with level + search filters ([#107](https://github.com/huntridge-labs/argus/issues/107)) ([c68a1c9](https://github.com/huntridge-labs/argus/commit/c68a1c93ba6258b7d7b1d333de315801cd3aa1ea))
* **view-terminal:** mouse-first interactivity — clickable everything ([#162](https://github.com/huntridge-labs/argus/issues/162)) ([d3fdc2a](https://github.com/huntridge-labs/argus/commit/d3fdc2a959959729426b38b754bfaf78c809eb24)), closes [#159](https://github.com/huntridge-labs/argus/issues/159) [#161](https://github.com/huntridge-labs/argus/issues/161)
* **view-terminal:** multi-select for batch export and clipboard ([#131](https://github.com/huntridge-labs/argus/issues/131)) ([87a46c1](https://github.com/huntridge-labs/argus/commit/87a46c19c417d5edfdb70f34167b9412cdea7174)), closes [#293](https://github.com/huntridge-labs/argus/issues/293)
* **view-terminal:** scan-over-scan diff overlay (D keybind) ([#132](https://github.com/huntridge-labs/argus/issues/132)) ([db07a1e](https://github.com/huntridge-labs/argus/commit/db07a1e2c98c9b3a0120f5b68ca3b55765cd731c))
* **view:** config-aware remediation + always-emit canonical argus-results.json ([#111](https://github.com/huntridge-labs/argus/issues/111)) ([2a33913](https://github.com/huntridge-labs/argus/commit/2a3391322c6ac173f1726fd4fdcca138c3850f08))

### Bug Fixes

* **actions:** container format flag, checkov tuple parse, zap flag name ([c2142a2](https://github.com/huntridge-labs/argus/commit/c2142a29c6b1d1e3e55f29f0a1168a6ad6f7ce4c))
* **actions:** rename misleading 'Install Argus SDK' step to 'Install dependencies' ([54a6430](https://github.com/huntridge-labs/argus/commit/54a64303a46a71ee60014b669551997dcb140fed))
* **actions:** use repeated --format flag (argparse append mode) ([f2ff3e3](https://github.com/huntridge-labs/argus/commit/f2ff3e35e0f3ffc5dcd33d94ffc5f3f9d491072e))
* CI failures — lazy requests import, example paths, Docker E2E test ([f5829ae](https://github.com/huntridge-labs/argus/commit/f5829aee66a2f04e15b5ed960309c13ebc5dad05))
* **ci:** add mcp dependency to requirements.txt and guard test imports ([a1dba86](https://github.com/huntridge-labs/argus/commit/a1dba866106e00b0d348a1d256a6c4d00dafd917))
* **ci:** add packages:read to test-actions and build-containers ([ce6f339](https://github.com/huntridge-labs/argus/commit/ce6f339b1de627a76036ec56e076e369bbebc20a))
* **ci:** add SDK schema path to release-it version bumper ([93e6de3](https://github.com/huntridge-labs/argus/commit/93e6de39d9251d8083b8b7b6549f9d552a4b9bd2))
* **ci:** build custom images before scanning, remove || true masks ([9a2152f](https://github.com/huntridge-labs/argus/commit/9a2152f6ca89ba157e3dd7826115d9ec35981638))
* **ci:** correct pypa/gh-action-pypi-publish SHA to v1.9.0 ([e131abb](https://github.com/huntridge-labs/argus/commit/e131abbacbcbcc8758cebcfb1a3003ee4910a805))
* **ci:** fix container scan PR comment showing identical collapsed titles ([1c170da](https://github.com/huntridge-labs/argus/commit/1c170da3455eecef6e24bbba1dbccfda85244c8f))
* **ci:** install all enabled scanner tools in dogfood workflow ([9e874d0](https://github.com/huntridge-labs/argus/commit/9e874d04e51dc7249ddfaee84ff3f0b867e77007))
* **ci:** install argus in the docs workflow so the architecture page renders ([af9b57a](https://github.com/huntridge-labs/argus/commit/af9b57a6953350186e79314506f301cb1abea7aa)), closes [#163](https://github.com/huntridge-labs/argus/issues/163)
* **ci:** move PyPI publish to release.yml protected environment ([6d5931c](https://github.com/huntridge-labs/argus/commit/6d5931c6b073232875e582730c935a2f07f679ec))
* **ci:** remove continue-on-error from test-actions scanner jobs ([dc42607](https://github.com/huntridge-labs/argus/commit/dc42607342298dceb0dd08273926f1da782cbcf6))
* **ci:** separate security findings from test fixture noise in PR comment ([a81d32c](https://github.com/huntridge-labs/argus/commit/a81d32cdbf91b95b6da7c4b9c200cdd097c7adde))
* **ci:** update CLI test job for timestamped run directories ([16bd55d](https://github.com/huntridge-labs/argus/commit/16bd55d121e2e3fcc02c1521c1faf70c486e5c9e))
* **ci:** update pypa/gh-action-pypi-publish to v1.14.0 ([228cc2a](https://github.com/huntridge-labs/argus/commit/228cc2acd711a8f44854dee4a530c76e0940b90b))
* **ci:** use commit SHA for pypa/gh-action-pypi-publish (not tag SHA) ([37d1804](https://github.com/huntridge-labs/argus/commit/37d18043e0f50908b1ef0bd366527cb1c15ee364))
* **ci:** use run_number for unique TestPyPI dev versions ([8563aa7](https://github.com/huntridge-labs/argus/commit/8563aa78a1bb1e729266fca772a2408948458b5d))
* **cli:** add explicit compdef for zsh completion when sourced directly ([e2e83a4](https://github.com/huntridge-labs/argus/commit/e2e83a4bcecc30212cc6c569a175bafb87c7f712))
* **cli:** context-aware zsh completion per scanner type ([1ccdfd9](https://github.com/huntridge-labs/argus/commit/1ccdfd9476efff10b019002ab05a749d901b6f0c))
* **cli:** fix argus classify method name and markdown report generation ([ec50f0f](https://github.com/huntridge-labs/argus/commit/ec50f0f83ce5f3a8ef7b818e563ff6afbcc9b457))
* **cli:** rewrite zsh completion with proper state machine pattern ([d06adb0](https://github.com/huntridge-labs/argus/commit/d06adb089415474549460717282feb0da4c311a0))
* **cli:** suppress zsh completion warning on eval ([ce64d5f](https://github.com/huntridge-labs/argus/commit/ce64d5f660efac00983b5615d545cf7408e50010))
* **container-scanner:** handle empty/malformed grype output without traceback ([#114](https://github.com/huntridge-labs/argus/issues/114)) ([8be445d](https://github.com/huntridge-labs/argus/commit/8be445d567d9baa09203c4bc45a25ca4a167996c))
* **container:** apply Docker fallback to actual CLI code path ([cc0e892](https://github.com/huntridge-labs/argus/commit/cc0e892fb92580dfc9e2ea76680f37c337cc0bc2))
* **container:** handle Grype source-scheme prefix collisions in image refs ([#115](https://github.com/huntridge-labs/argus/issues/115)) ([d7c94dc](https://github.com/huntridge-labs/argus/commit/d7c94dc601380aa215ebdcc45d83b63bf05ad162))
* **container:** mount docker.sock for local images, surface scan failures ([4099890](https://github.com/huntridge-labs/argus/commit/4099890924f8c12c625c8516176d706ccf25b643))
* **container:** parse_container_config accepts unwrapped inner-mapping shape ([#113](https://github.com/huntridge-labs/argus/issues/113)) ([267e4be](https://github.com/huntridge-labs/argus/commit/267e4be01bd8f2fd7153072c4f2b4b56a1b2613c))
* **container:** pre-warm scanner DBs and update image pins ([33307eb](https://github.com/huntridge-labs/argus/commit/33307eb8b7955913c9cd88806fe1f420bcd36e11))
* **container:** surface dockerfile in artifacts and write argus-audit.json ([#123](https://github.com/huntridge-labs/argus/issues/123)) ([18f5d03](https://github.com/huntridge-labs/argus/commit/18f5d039bba4d78987bc002aaf688ab3f6c35d3c))
* **container:** wire exposure + services into the scan-container CLI path ([b1961ce](https://github.com/huntridge-labs/argus/commit/b1961cedad3c7d3df987a9da7a3119b70a706a0f))
* **dast:** support URL-based targets in DastEngine ([31e5cf0](https://github.com/huntridge-labs/argus/commit/31e5cf001b6f838cdac2d8442f6ef0dfd04042f0))
* **deps:** add 7-day stabilization delay and cover all Dockerfile tool versions ([3a822f9](https://github.com/huntridge-labs/argus/commit/3a822f9f8b57c1dfa912b90fbb8043f27f31a5f2))
* **dev:** improve local/devcontainer setup ([a8ea1fd](https://github.com/huntridge-labs/argus/commit/a8ea1fd59490a86cff0a7c8ae320a34590139e8d))
* **docker:** patch Alpine OS-level vulnerabilities in all images ([0ead1b3](https://github.com/huntridge-labs/argus/commit/0ead1b3e42136c3624d308006e662df9a27e56b8))
* **docker:** update tool versions and drop checkov from CLI image ([d9a01ca](https://github.com/huntridge-labs/argus/commit/d9a01ca2e2443e93810f59f14607f3b0fc6753f7))
* **docs:** remove hardcoded workflow nav from docsite builder ([80fd2e6](https://github.com/huntridge-labs/argus/commit/80fd2e6d92895652e0df773dd94e79432de51abe))
* dogfood scan now actually scans what we ship ([#106](https://github.com/huntridge-labs/argus/issues/106)) ([a3ad04a](https://github.com/huntridge-labs/argus/commit/a3ad04a7308d52e74e218934cd90e0cd3ebaa1f8))
* **engine:** auto backend falls back to local when container pull fails ([fbe3c94](https://github.com/huntridge-labs/argus/commit/fbe3c944c4450ce71bcc4fa6c8104514210e1881))
* **engine:** defer to scanner.scan when build_args is missing ([#120](https://github.com/huntridge-labs/argus/issues/120)) ([ff69b42](https://github.com/huntridge-labs/argus/commit/ff69b42a8bdb6bed4aad08f6a862dfc92e3fb600))
* **engine:** make container /output dir writable for non-root scanner users ([#110](https://github.com/huntridge-labs/argus/issues/110)) ([79def1a](https://github.com/huntridge-labs/argus/commit/79def1acb1d2387ceebd0a5b263ce43011444bcb))
* **engine:** pass credentials by name, not value, on docker run ([#144](https://github.com/huntridge-labs/argus/issues/144)) ([37e433d](https://github.com/huntridge-labs/argus/commit/37e433dc602f1b04e7dabec3955d88d9afa66d77)), closes [#1](https://github.com/huntridge-labs/argus/issues/1)
* **engine:** surface scanner exceptions as failure rows in canonical results ([#119](https://github.com/huntridge-labs/argus/issues/119)) ([927e572](https://github.com/huntridge-labs/argus/commit/927e57201d4327aaef0bf1a5ab50cba2789df193))
* **engine:** treat severity_threshold 'none' as no threshold ([486a784](https://github.com/huntridge-labs/argus/commit/486a784bf95bd9fa59f7d92c8c7c1314fa57737f))
* **examples:** drop unsupported inputs from scanner-zap / -container / -gitleaks usages ([#134](https://github.com/huntridge-labs/argus/issues/134)) ([7cfb89b](https://github.com/huntridge-labs/argus/commit/7cfb89b0ef51e4908d1a23c1ddcebbfb2059083c))
* **examples:** remove duplicate workflow, fix stale refs and README ([1bd9bca](https://github.com/huntridge-labs/argus/commit/1bd9bca6b97d52af5667a8cd64d07d0859c02772))
* **mcp:** print startup banner to stderr so the server isn't silent ([#99](https://github.com/huntridge-labs/argus/issues/99)) ([9613810](https://github.com/huntridge-labs/argus/commit/96138101dd78b25c203fce913ae2944410236f3a))
* **publish:** update dev versioning to ensure monotonic order for TestPyPI releases ([8c759a3](https://github.com/huntridge-labs/argus/commit/8c759a3427a5602924aa6b9400777760e62b44c5))
* **pypi:** correct documentation URL to GitHub Pages docsite ([a21f2d5](https://github.com/huntridge-labs/argus/commit/a21f2d5b9eb9801e6ad172631c84deee8f7c126a))
* **pypi:** sync pyproject.toml with website and correct license ([ad5bd83](https://github.com/huntridge-labs/argus/commit/ad5bd83433a6fe320503b7abca60741d7097b101))
* **release:** add package.json to release-it version bumper ([6b41048](https://github.com/huntridge-labs/argus/commit/6b41048d7f063c092e8f6ce98763243f57c2bbc7))
* **release:** drop redundant package.json regex-bumper rule ([afecbbd](https://github.com/huntridge-labs/argus/commit/afecbbdff36b3c7b28786c88dea44e175c0deeb1))
* **release:** install [all] extras so dry-run pytest can collect ([4576d21](https://github.com/huntridge-labs/argus/commit/4576d2176028ad8f7317a13dbdf6588293b8b81c))
* **sbom:** osv-scanner v2 compatibility and scanner robustness ([#95](https://github.com/huntridge-labs/argus/issues/95)) ([31c514d](https://github.com/huntridge-labs/argus/commit/31c514d1af487cf942a6f3f14f8fd468ed7811db))
* **sbom:** surface scanner failures, SPDX-2.1 and purl-coverage warnings ([2842544](https://github.com/huntridge-labs/argus/commit/284254446e4c879e9ce103dce7cdcda76cff149a))
* **scan:** make --sbom directory batches resilient to per-file failures ([e48b88a](https://github.com/huntridge-labs/argus/commit/e48b88ac6cd82157313487c1175d2d35fa45e247))
* **scanners:** auto-discover tool configs; make exclude merge correct ([#93](https://github.com/huntridge-labs/argus/issues/93)) ([7e3ad77](https://github.com/huntridge-labs/argus/commit/7e3ad77d3dd4bf682fc7341c23505de487b1e4de))
* **scanners:** correct execution-failure signaling and OSV container entrypoint ([#125](https://github.com/huntridge-labs/argus/issues/125)) ([651c10b](https://github.com/huntridge-labs/argus/commit/651c10b86f4bd770595c18a46335398807e9147f))
* **scanners:** document and fix 4 known scanner quirks ([111327c](https://github.com/huntridge-labs/argus/commit/111327cb63f57adada0523b1682b647f87535cce))
* **scanners:** pin OSV-Scanner to v2.3.5 and add image alias mapping ([7b8ae7d](https://github.com/huntridge-labs/argus/commit/7b8ae7de4351cea0f000eaec4ca7991b7e6dbaed))
* **scanners:** pre-pull Docker images and add container fallback ([e9db64e](https://github.com/huntridge-labs/argus/commit/e9db64e55f97e36bd290727a7b991dbb2c2fd2ef))
* **scn:** 6 classifier improvements from live testing ([91d22ce](https://github.com/huntridge-labs/argus/commit/91d22ce2e0cac5fb90c89001e14568344f7a9598))
* **sdk:** add universal post-scan exclude filter in engine ([0d7a83f](https://github.com/huntridge-labs/argus/commit/0d7a83fd13be07bdf51bb3e626a4f925449edbbf))
* **sdk:** derive container_args from config, not hardcoded values ([86db23c](https://github.com/huntridge-labs/argus/commit/86db23c478bc4853b80c86d22670ef733eaf556d))
* **sdk:** exclude active log file from audit manifest hash inventory ([089d7bd](https://github.com/huntridge-labs/argus/commit/089d7bdbb544350c5480f7ec3163b1959d13c6f1))
* **sdk:** fix --list flag using wrong attribute name in CLI ([6a5fd57](https://github.com/huntridge-labs/argus/commit/6a5fd57c8b5d3971d2d49229756360e2c3ecb7ab))
* **sdk:** remove hard disk floor, try scans and handle failures ([a54b081](https://github.com/huntridge-labs/argus/commit/a54b0811713028e42dfdfd311e316ed5525e3cc0))
* **sdk:** sync __version__ with version.yaml and add to release-it ([ee48bb4](https://github.com/huntridge-labs/argus/commit/ee48bb4f6b9fa0797cd4488f236237f23ab2b65c))
* **sdk:** validate scanner name with fuzzy 'did you mean?' suggestions ([3084f68](https://github.com/huntridge-labs/argus/commit/3084f685e83a59c1a85cc228da238ad24b0d7177))
* **security:** redact secret values at the scanner parser ([#101](https://github.com/huntridge-labs/argus/issues/101)) ([1324b7d](https://github.com/huntridge-labs/argus/commit/1324b7de06b581a93e3a1b4e01e7a31a42c90dec))
* **test-fixtures:** bump flask/werkzeug floor past known-CVE versions ([#160](https://github.com/huntridge-labs/argus/issues/160)) ([f893517](https://github.com/huntridge-labs/argus/commit/f893517223b5150ba366f111f40f97c6f554f9a2))
* **validate:** catch typos in containers config and close self-scan UX gaps ([#118](https://github.com/huntridge-labs/argus/issues/118)) ([0bf1a26](https://github.com/huntridge-labs/argus/commit/0bf1a26bee5c36f2baf00d17f86e6a1e10b690ad))
* **view-browser:** actually elevate header above main for dropdown overlay ([#108](https://github.com/huntridge-labs/argus/issues/108)) ([b6a7861](https://github.com/huntridge-labs/argus/commit/b6a786116751fa1813b54a8452912393fb868691)), closes [#105](https://github.com/huntridge-labs/argus/issues/105)
* **view-browser:** elevate header so Recent runs dropdown overlays main content ([#105](https://github.com/huntridge-labs/argus/issues/105)) ([3144137](https://github.com/huntridge-labs/argus/commit/31441375b3e05dc58795a6014436f98f64e3bc90))

### Dependencies

* **deps:** bump scanner tool versions to current latest stable ([#104](https://github.com/huntridge-labs/argus/issues/104)) ([fdd43e6](https://github.com/huntridge-labs/argus/commit/fdd43e68ba0f2a2cd467782b8132b892d49e64a9))

### Maintenance

* **.ai:** add commands to build local scanner images and update quick reference ([3da0a07](https://github.com/huntridge-labs/argus/commit/3da0a0744517dd8de704a53e8c5e259fb515b40c))
* **actions:** delete dead scripts and tests from container and zap ([bd3fc12](https://github.com/huntridge-labs/argus/commit/bd3fc12fbb52526637112859be65c188b28a8a06))
* **actions:** delete dead scripts and tests from refactored scanners ([9596469](https://github.com/huntridge-labs/argus/commit/959646996ec865b5c40024e7c43d99e9c29c30c1))
* **engine:** improve pull progress messaging and close roadmap items ([705ca60](https://github.com/huntridge-labs/argus/commit/705ca6099ed7b9769f4f88abda39eab80135ec1c))
* **release:** Phase 4 release-blocker cleanup ([#153](https://github.com/huntridge-labs/argus/issues/153)) ([c58fcd3](https://github.com/huntridge-labs/argus/commit/c58fcd3a96d423394567012740ef27640700c28a))
* **supply-chain:** pin Dockerfile FROMs, migrate to pnpm, raise Python dep floors ([#161](https://github.com/huntridge-labs/argus/issues/161)) ([3ff9155](https://github.com/huntridge-labs/argus/commit/3ff915588ec0321f1807b6a81141908aec9a4199)), closes [#151](https://github.com/huntridge-labs/argus/issues/151)
* **supply-chain:** pin every OFFICIAL_IMAGE to a [@sha256](https://github.com/sha256): digest ([#151](https://github.com/huntridge-labs/argus/issues/151)) ([a97643e](https://github.com/huntridge-labs/argus/commit/a97643e09126503a98854aebb90378684ea5ef2a))


### Documentation

* add argus.yml configuration reference ([ac9af33](https://github.com/huntridge-labs/argus/commit/ac9af332eb5686155825c4ab1e5a3d9ea488c105))
* add linter registration to CLAUDE.md, CONTRIBUTING.md, and AICaC ([cc60fd6](https://github.com/huntridge-labs/argus/commit/cc60fd6f310e4ac46a228a029b7d634a7fd2f443))
* add portability research and ADR-013 for cross-platform architecture ([1774613](https://github.com/huntridge-labs/argus/commit/17746130344402432d2c93aece54cc36252e33ab))
* add PyPI README, MCP docs, and AI context updates ([39e40d5](https://github.com/huntridge-labs/argus/commit/39e40d5cc16a4bdd19a898c6f82c43f0ec8fc053))
* **adr-021:** formalize SDK-vs-composite-action boundary; close roadmap [#206](https://github.com/huntridge-labs/argus/issues/206) ([#137](https://github.com/huntridge-labs/argus/issues/137)) ([317cbfe](https://github.com/huntridge-labs/argus/commit/317cbfe43a9392a63c7b9cbd50abd03f0e42643d))
* **adr-024:** decide scanner-zap config-passthrough; minimal action surface ([#141](https://github.com/huntridge-labs/argus/issues/141)) ([2a29eac](https://github.com/huntridge-labs/argus/commit/2a29eaca5cdc6ac795c6b746df86526fe8fd3512))
* **adr-025:** split OS-image scope — services sub-scanner in, VM-image out ([#157](https://github.com/huntridge-labs/argus/issues/157)) ([8002741](https://github.com/huntridge-labs/argus/commit/8002741007366a192c13d252119b0149fe4aa07a))
* **ai:** refresh .ai/ context for SDK-first reality ([fa22779](https://github.com/huntridge-labs/argus/commit/fa227794eab3d3cce3326d72334f967c209a7060)), closes [#111](https://github.com/huntridge-labs/argus/issues/111)
* audit pass on README, scanners.md, and .ai/architecture.yaml ([#155](https://github.com/huntridge-labs/argus/issues/155)) ([7cbd5ea](https://github.com/huntridge-labs/argus/commit/7cbd5eac5d417f1527da82621c95f15829551bd3))
* **cli:** clarify 'argus completion' help with reload step and Tab examples ([29e77b4](https://github.com/huntridge-labs/argus/commit/29e77b4280f8ec503b56c5d95bd02f396caadbba))
* close scanner-container scan_mode + gitleaks notify_users decisions ([#156](https://github.com/huntridge-labs/argus/issues/156)) ([12151c4](https://github.com/huntridge-labs/argus/commit/12151c493d2a072daaf4e68e4b17668b0a578e68))
* **developer:** add TestPyPI validation guide with Claude prompt ([b3a7f65](https://github.com/huntridge-labs/argus/commit/b3a7f656901fde81c06d99f19da3cc320baaa242))
* **developer:** document container image build and release lifecycle ([a4a293e](https://github.com/huntridge-labs/argus/commit/a4a293e750159c3845a67b973aa5177c2e3cf52a))
* **docsite:** SDK-first nav + CI peer integrations + completion setup ([#150](https://github.com/huntridge-labs/argus/issues/150)) ([8b8269d](https://github.com/huntridge-labs/argus/commit/8b8269dfcf6333df46a3d23a1cb3fe2a8c763607))
* **docsite:** version-aware GITHUB_BLOB ref instead of hardcoded main ([#152](https://github.com/huntridge-labs/argus/issues/152)) ([922c1c8](https://github.com/huntridge-labs/argus/commit/922c1c8f0805068a2d944fb517af1931e3e056b4)), closes [#150](https://github.com/huntridge-labs/argus/issues/150)
* **examples:** add SDK-based CI examples for 4 platforms ([7cd131f](https://github.com/huntridge-labs/argus/commit/7cd131fb64e65a55982734717cbcdd1386d3c631))
* **mcp:** per-client config + uvx zero-install + registry tracker ([#100](https://github.com/huntridge-labs/argus/issues/100)) ([66f849a](https://github.com/huntridge-labs/argus/commit/66f849a48732aaf777bde554f68113908f75d692))
* migration guide, CI integration pattern, and cleanup verification ([27f3cc6](https://github.com/huntridge-labs/argus/commit/27f3cc6c4dcece01b7da2d95762d82fa697d4562))
* **pypi:** add cover image to PyPI README via raw.githubusercontent.com ([bf0986b](https://github.com/huntridge-labs/argus/commit/bf0986bc098db384b5d0d681cb3660219e6bf905))
* **roadmap:** add build & dependency hygiene follow-ups ([1c42c88](https://github.com/huntridge-labs/argus/commit/1c42c8833d125cfe0e8168d1d408a12a01db7c19))
* **roadmap:** capture secret-handling audit + hardening PR queue ([#143](https://github.com/huntridge-labs/argus/issues/143)) ([cd0b13f](https://github.com/huntridge-labs/argus/commit/cd0b13ffe8d9dec1238f9dcc1212c2a4ee40bf80)), closes [#142](https://github.com/huntridge-labs/argus/issues/142)
* **roadmap:** close shipped scanner-zap config-passthrough items ([52a18ce](https://github.com/huntridge-labs/argus/commit/52a18ce50b7bfc39c457bd2160f04d3e37e79909)), closes [#142](https://github.com/huntridge-labs/argus/issues/142)
* **roadmap:** consolidate completed work, highlight 11 remaining items ([697e5db](https://github.com/huntridge-labs/argus/commit/697e5db8ac739392be290aad99a4beddc35f91cd))
* **roadmap:** mark 6 completed items, remove duplicate entry ([2f0ed9e](https://github.com/huntridge-labs/argus/commit/2f0ed9ed220502fd8748d4ba9e66981d289892ae))
* **roadmap:** mark shipped items as complete ([e4aa95d](https://github.com/huntridge-labs/argus/commit/e4aa95d648bd861726dc9a3537acecac5391d1a9))
* **roadmap:** track container port exposure + OS-image research item ([#147](https://github.com/huntridge-labs/argus/issues/147)) ([41305e9](https://github.com/huntridge-labs/argus/commit/41305e92d2326f2b6c7e5e0896c35b75c76c8164))
* **roadmap:** track DAST + container scanner regressions vs 0.6.8 ([#135](https://github.com/huntridge-labs/argus/issues/135)) ([12fc7cc](https://github.com/huntridge-labs/argus/commit/12fc7cc6a913f9c8cf635ef42ebbd3346cfd0978))
* **roadmap:** trim the SDK migration log for merge to main ([0463977](https://github.com/huntridge-labs/argus/commit/04639772550b097f2d6ec14fdc3892aa4fec9a93))
* **sdk:** add MCP server phase, CI config health to roadmap, ADR-015 ([d837b29](https://github.com/huntridge-labs/argus/commit/d837b299129c37dd901f3c9ffbccb5834c6d0cb1))
* **sdk:** add performance research items to roadmap ([7b9a355](https://github.com/huntridge-labs/argus/commit/7b9a3552f71678a42c6c423595f557c12fe171fd))
* **sdk:** add Phase 3 Docker execution backend design and ADR-014 ([6ec7779](https://github.com/huntridge-labs/argus/commit/6ec77798903e25b7c797c806ed9324326dcf6077))
* **sdk:** add post-PyPI cleanup items to roadmap ([5503570](https://github.com/huntridge-labs/argus/commit/55035703a75364f8ebd7d3e934b530508d147328))
* **sdk:** add SCN classifier improvement items to roadmap ([83d84c6](https://github.com/huntridge-labs/argus/commit/83d84c60b81913843c86c217c81404bef647849e))
* **sdk:** add SDK roadmap tracking remaining Phase 3-4 work ([a95e979](https://github.com/huntridge-labs/argus/commit/a95e979bab0aa28e7f4ca4e338ce41a934a2f44a))
* **sdk:** add testing strategy with ref lifecycle and argus-test plan ([0e9cb3a](https://github.com/huntridge-labs/argus/commit/0e9cb3ac21338b5f7368134f9c598b82635da127)), closes [#29](https://github.com/huntridge-labs/argus/issues/29)
* **sdk:** add TestPyPI flag removal to post-release checklist ([1e6b7a1](https://github.com/huntridge-labs/argus/commit/1e6b7a193faa4b456a8450b95058efa3afb46178))
* **sdk:** mark --exclude and report tests as complete on roadmap ([0395466](https://github.com/huntridge-labs/argus/commit/039546687544caef993e500b8df96699bd06b287))
* **sdk:** mark 10 more items complete on roadmap ([d9269d6](https://github.com/huntridge-labs/argus/commit/d9269d69d30e309a0e55d24bf2436d82b49f0b64))
* **sdk:** mark SCN detector port as complete on roadmap ([84f6843](https://github.com/huntridge-labs/argus/commit/84f68438a4f5a07e099f58923ca05f30c9043944))
* **sdk:** mark SDK docs as complete — covered by existing auto-generated references ([916022d](https://github.com/huntridge-labs/argus/commit/916022dc45df152d324479dfda028bebd58c17bb))
* **sdk:** reframe Phase 5 as agentic substrate (CLI + MCP + skill) ([0c3a69f](https://github.com/huntridge-labs/argus/commit/0c3a69f9ef9f02507ff11004c98a7916dabb5ab6))
* **sdk:** scope SCN detector port as argus classify subcommand ([e5b679e](https://github.com/huntridge-labs/argus/commit/e5b679e9f3a946119952ed5b08cc57c3f1573492))
* **sdk:** sync roadmap with all completed and remaining work ([8e8598a](https://github.com/huntridge-labs/argus/commit/8e8598af50a0ed066011ccd947eaeea4b12fc095))
* **sdk:** update roadmap — 8 of 10 scanner wrappers complete ([1be8d98](https://github.com/huntridge-labs/argus/commit/1be8d9848b922a2ba115f0c3b4cab217d775238d))
* **sdk:** update roadmap — PyPI publishing and container publishing complete ([eb0aa61](https://github.com/huntridge-labs/argus/commit/eb0aa61cd629718533f57f119d604727b5613422))
* **sdk:** update roadmap with linter module and wrapper completion ([4a5f055](https://github.com/huntridge-labs/argus/commit/4a5f055d33f2e99078507105d9739b7cf792f8a9))
* **sdk:** update roadmap with Phase 3 progress and completed items ([1ac7e41](https://github.com/huntridge-labs/argus/commit/1ac7e416efdb5ff81ccedc3c2401579b557f39d2))
* **sdk:** update roadmap with thin wrapper rollout progress ([5897543](https://github.com/huntridge-labs/argus/commit/58975437d04ce2632f55b40de678b1ccf7cf851f))
* **troubleshooting:** add docker troubleshooting guide ([#129](https://github.com/huntridge-labs/argus/issues/129)) ([9373f35](https://github.com/huntridge-labs/argus/commit/9373f356859f0524a56a341e214aa12b84c63f87)), closes [#125](https://github.com/huntridge-labs/argus/issues/125) [#125](https://github.com/huntridge-labs/argus/issues/125) [#623](https://github.com/huntridge-labs/argus/issues/623)
* update CLAUDE.md and CONTRIBUTING.md for SDK-first architecture ([5a64bbe](https://github.com/huntridge-labs/argus/commit/5a64bbe61f90c849a8356b69e0285b647eb49666))
* update install instructions for pip install argus-security ([04e01b7](https://github.com/huntridge-labs/argus/commit/04e01b7b2747ad48f6e1eb53062619f30785bd76))
* **view-terminal:** SVG screenshot pass + self-contained capture pipeline ([#159](https://github.com/huntridge-labs/argus/issues/159)) ([a64d841](https://github.com/huntridge-labs/argus/commit/a64d841e29617040cda5bae457c601db4e443ed0))
* **zap:** deprecation note in action.yml + 0.6.x → 1.x migration guide ([#154](https://github.com/huntridge-labs/argus/issues/154)) ([c365d16](https://github.com/huntridge-labs/argus/commit/c365d16734c72e1107981e33158b4a3752be02a3)), closes [#136](https://github.com/huntridge-labs/argus/issues/136)

### Code Refactoring

* **actions:** remove manual tool installs — SDK auto-sources via Docker ([f9f8435](https://github.com/huntridge-labs/argus/commit/f9f8435df195ed2631ec81d75a481efa5a30968e))
* **actions:** thin wrapper for all 6 linter actions ([c47b89a](https://github.com/huntridge-labs/argus/commit/c47b89a781a04655fec22ac77056228973437caf))
* **actions:** thin wrapper for container and zap — all 10 scanners complete ([e6f2e95](https://github.com/huntridge-labs/argus/commit/e6f2e95528a5926ea14c02ed393ca53ccb4c2b52))
* **actions:** thin wrapper rollout for gitleaks, osv, checkov ([4bd6536](https://github.com/huntridge-labs/argus/commit/4bd653617bad1065df775500c8eb87e7a9990638))
* **actions:** thin wrapper rollout for opengrep, clamav, trivy-iac, supply-chain ([6e539ed](https://github.com/huntridge-labs/argus/commit/6e539ed44ae71f2fd54794d63bf6cedbb59ab299))
* **ci:** consolidate container build/scan/test into one workflow ([0417453](https://github.com/huntridge-labs/argus/commit/041745326ac9d315af5bdb8602655ce33438242e))
* **ci:** remove deprecated scanner wrapper and orchestrator workflows ([1a0cb24](https://github.com/huntridge-labs/argus/commit/1a0cb2472fa89ef9be55cc490c147074ea413f7d))
* **ci:** remove manual tool installs from workflows ([372a340](https://github.com/huntridge-labs/argus/commit/372a3408160d0dff794831f1c678d1369c92a473))
* **ci:** split release and publish into tag-triggered workflow ([afcc37c](https://github.com/huntridge-labs/argus/commit/afcc37c4107b025dc3fdc83d249926a64c24025c))
* **ci:** use argus reporter and comment-pr action for container scans ([a840c69](https://github.com/huntridge-labs/argus/commit/a840c6954aaffe2a6bb7412e77012ec30189e3fd))
* **cli:** unify browse/serve into a single `argus view` command ([#103](https://github.com/huntridge-labs/argus/issues/103)) ([b969cd2](https://github.com/huntridge-labs/argus/commit/b969cd2519b269450a57fa25a2410ea27b93847a))
* **deps:** convert renovate.json to renovate.yaml ([2207201](https://github.com/huntridge-labs/argus/commit/2207201bd927641e50fbdc856e378d293501d39d))
* **init:** drop --platform, enhance detection, add linter support ([bb27c1f](https://github.com/huntridge-labs/argus/commit/bb27c1f2a817553a7410d13ccf910aac02b77151))
* **linters:** FileDiscoveryScanner template + shared docker-fallback helper ([#133](https://github.com/huntridge-labs/argus/issues/133)) ([b83585d](https://github.com/huntridge-labs/argus/commit/b83585da2d6f53186773da660877adf6b970b529))
* **linting-summary:** apply silent-failure audit (status table + gating) ([#128](https://github.com/huntridge-labs/argus/issues/128)) ([eb3c751](https://github.com/huntridge-labs/argus/commit/eb3c751f3be6b957d440e4801723b9866fb3e282)), closes [#91](https://github.com/huntridge-labs/argus/issues/91)
* **scanners:** unify tool_version + scan + build_args into a single SDK pattern ([#117](https://github.com/huntridge-labs/argus/issues/117)) ([4f03e7b](https://github.com/huntridge-labs/argus/commit/4f03e7bbe61115a122ea485b0e92be6de15a2509))
* **sdk:** auto-discover config and simplify all action wrappers ([d597dd6](https://github.com/huntridge-labs/argus/commit/d597dd6949755df88614c887de348af9d9bdb368))
* **sdk:** collapse container into argus scan container ([ca296a3](https://github.com/huntridge-labs/argus/commit/ca296a356849234e1169f59822f31e5344bbe08c))
* **wrappers:** close silent-failure paths in reusable-security-hardening ([#91](https://github.com/huntridge-labs/argus/issues/91)) ([35e993c](https://github.com/huntridge-labs/argus/commit/35e993cb2f7d57b7d8693d9ee298140f9273e96b))
* **wrappers:** install-from-source pattern, bin/argus removal, ADR-019 + CI guard ([#126](https://github.com/huntridge-labs/argus/issues/126)) ([2c5c8b4](https://github.com/huntridge-labs/argus/commit/2c5c8b41fc89e67871c2a063dc0643dfa3194e50)), closes [#201](https://github.com/huntridge-labs/argus/issues/201) [#125](https://github.com/huntridge-labs/argus/issues/125)

### Tests

* add E2E tests, module routing tests, and image manifest CI check ([51a44a8](https://github.com/huntridge-labs/argus/commit/51a44a8106465720a3021c4f69da05c75571cca3))
* add pytest tests for version refs, action schemas, and security summary ([456b7fb](https://github.com/huntridge-labs/argus/commit/456b7fb3e69b7566f9e9c70369fb7cd26e56bb24))
* close testing gaps — Docker E2E, container dedup, --version ([3639040](https://github.com/huntridge-labs/argus/commit/3639040f18226b04b7bf8ada01593e32bfc05ff7))
* **engine:** add 33 tests for exclusion system ([21bb376](https://github.com/huntridge-labs/argus/commit/21bb37654adc4e4a4e435685de8b8eaed7ec7ffe))
* **engine:** add tests for fail-fast, timeout, and severity 'none' fix ([3a39dfc](https://github.com/huntridge-labs/argus/commit/3a39dfc80e5a5a92469ed57b465dcab34eab8caa))
* fix E2E tests and exclude [@slow](https://github.com/slow) from default pytest run ([b9167da](https://github.com/huntridge-labs/argus/commit/b9167da4544e2619c1bed87aca1c53ee69464a60))
* **sdk:** add 134 tests for container, DAST, CLI, and scanner coverage ([9c1224a](https://github.com/huntridge-labs/argus/commit/9c1224ab9f56d9bcdd8e3c50c5e413fed2160730))
* **sdk:** add comprehensive test suite and update project config ([cd8d18f](https://github.com/huntridge-labs/argus/commit/cd8d18f4a3ed9c4290aaf69102063cbf0cec05df))
* **sdk:** add integration tests for CLI, engine Docker paths, and supply chain config ([1454a09](https://github.com/huntridge-labs/argus/commit/1454a0960e75ae83901a6084df70afa52253ae46))
* **sdk:** add tests for Docker execution backend and container registry ([55d1f07](https://github.com/huntridge-labs/argus/commit/55d1f0707d56c311b138549e341d832ee9facfb2))

### Continuous Integration

* audit example with-keys against current action.yml input contracts ([#136](https://github.com/huntridge-labs/argus/issues/136)) ([106bfbd](https://github.com/huntridge-labs/argus/commit/106bfbd724d5bd6a49b51377492c5491680d72e6)), closes [#134](https://github.com/huntridge-labs/argus/issues/134)
* **ghcr:** nightly cleanup of non-semver tags ([4614ad4](https://github.com/huntridge-labs/argus/commit/4614ad47d072c2feabfc3fa9456b82fe0900564d))
* **release:** build-once-promote-everywhere release pipeline ([6f2e111](https://github.com/huntridge-labs/argus/commit/6f2e11197093b26a24d131ccb8c72081c4d5b22a))
* shared argus_smoke.sh helper retries the GHA Python 3.13 SIGSEGV flake everywhere ([#127](https://github.com/huntridge-labs/argus/issues/127)) ([849b6df](https://github.com/huntridge-labs/argus/commit/849b6df45653c6210eef2a57148fbe80aa3f4995)), closes [#125](https://github.com/huntridge-labs/argus/issues/125) [#126](https://github.com/huntridge-labs/argus/issues/126)
* trigger pipeline to verify GHCR public container pulls ([d90e617](https://github.com/huntridge-labs/argus/commit/d90e617a87586f7723bc59ed58cc715a039b4b16))

## [0.7.2](https://github.com/huntridge-labs/argus/compare/0.7.1...0.7.2) (2026-04-17)

### Bug Fixes

* **container-scan:** update argus checkout ref to 0.7.1 and add ([67f2a9f](https://github.com/huntridge-labs/argus/commit/67f2a9ff3b2af53ece6f43d0d9df748205c60f53))

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
