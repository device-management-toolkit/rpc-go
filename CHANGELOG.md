## [2.48.15](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.14...v2.48.15) (2026-01-15)


### Bug Fixes

* workaround for fixing crash in formated logs ([996b559](https://github.com/device-management-toolkit/rpc-go/commit/996b5599a2ba23e4e5842d248f6b840f8e8568d2))

## [2.48.14](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.13...v2.48.14) (2026-01-12)

## [2.48.13](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.12...v2.48.13) (2026-01-06)


### Bug Fixes

* capturing stdout and stderr to output variable ([b6dc09e](https://github.com/device-management-toolkit/rpc-go/commit/b6dc09ebb1c6aadf8a708602d382ce9189747a11))

## [2.48.12](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.11...v2.48.12) (2026-01-06)


### Bug Fixes

* apply SkipAmtCertCheck flag to all TLS configurations ([#1080](https://github.com/device-management-toolkit/rpc-go/issues/1080)) ([eb056e7](https://github.com/device-management-toolkit/rpc-go/commit/eb056e7ecc46aaf67e620abfeccedebc5ee92bf7)), closes [#1068](https://github.com/device-management-toolkit/rpc-go/issues/1068)

## [2.48.11](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.10...v2.48.11) (2026-01-05)


### Bug Fixes

* bypasses hostname verification for AMT 19+ certificates with -n or -skipamtcertcheck ([#1071](https://github.com/device-management-toolkit/rpc-go/issues/1071)) ([41cc832](https://github.com/device-management-toolkit/rpc-go/commit/41cc832b9b83c52f2d30408f01f4b105824db215))

## [2.48.10](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.9...v2.48.10) (2025-12-10)


### Bug Fixes

* reject invalid UUIDs during activation ([dba3b6e](https://github.com/device-management-toolkit/rpc-go/commit/dba3b6e4afb4a9a9fe0abdf4db676cf5ca84dab4)), closes [#480](https://github.com/device-management-toolkit/rpc-go/issues/480)

## [2.48.9](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.8...v2.48.9) (2025-12-02)

## [2.48.8](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.7...v2.48.8) (2025-11-18).


### Bug Fixes

* --local issue with wired 8021x configure failing ([f9c0a7a](https://github.com/device-management-toolkit/rpc-go/commit/f9c0a7a1c72e1afe24f9bf0ae609a05278967b78))

## [2.48.7](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.6...v2.48.7) (2025-11-06)

## [2.48.6](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.5...v2.48.6) (2025-11-04)


### Bug Fixes

* add -n to all the configure subcommands ([c5a4232](https://github.com/device-management-toolkit/rpc-go/commit/c5a423297f89c481e9c9e16c77aea9f27611a696))

## [2.48.5](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.4...v2.48.5) (2025-10-23)


### Bug Fixes

* cert cleanup now excludes mpsroot cert ([9e98143](https://github.com/device-management-toolkit/rpc-go/commit/9e981433d1d67397230959063639bb070ad06d27))

## [2.48.4](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.3...v2.48.4) (2025-10-13)

## [2.48.3](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.2...v2.48.3) (2025-10-13)


### Bug Fixes

* address panic when operationalState is requested ([#985](https://github.com/device-management-toolkit/rpc-go/issues/985)) ([b16ac56](https://github.com/device-management-toolkit/rpc-go/commit/b16ac56c1ab81970df9926212caa99dd60a8e2e6)), closes [#978](https://github.com/device-management-toolkit/rpc-go/issues/978)
* **dockerfile:** license comment now correct ([74d13b3](https://github.com/device-management-toolkit/rpc-go/commit/74d13b31d491909da14e00d281cb8d2e52d57c42))

## [2.48.2](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.1...v2.48.2) (2025-07-03)


### Bug Fixes

* **deps:** update go-wsman-messages calls to use pointers for PUT ([c276a0d](https://github.com/device-management-toolkit/rpc-go/commit/c276a0d74b864898a123680f23c8c4f381cd2e90))

## [2.48.1](https://github.com/device-management-toolkit/rpc-go/compare/v2.48.0...v2.48.1) (2025-07-03)


### Reverts

* leverage kong cli for better organization of cli commands ([2386bdb](https://github.com/device-management-toolkit/rpc-go/commit/2386bdb3e04cfb1b3476c29b49c27bde5b32be09))

# [2.48.0](https://github.com/device-management-toolkit/rpc-go/compare/v2.47.3...v2.48.0) (2025-07-01)


### Features

* adds UEFIWiFiSyncEnabled is added to config for OCR ([bc4855d](https://github.com/device-management-toolkit/rpc-go/commit/bc4855d65af38a800da21afe13d69f5f06f5edfc))

## [2.47.3](https://github.com/device-management-toolkit/rpc-go/compare/v2.47.2...v2.47.3) (2025-06-17)


### Bug Fixes

* address panic when incorrect URL for RPS ([72cf72e](https://github.com/device-management-toolkit/rpc-go/commit/72cf72e59a3dccf766e2810e0680dca3cbb9c3bd))

## [2.47.2](https://github.com/device-management-toolkit/rpc-go/compare/v2.47.1...v2.47.2) (2025-06-09)


### Bug Fixes

* add seperate check to skip amt cert verification ([#858](https://github.com/device-management-toolkit/rpc-go/issues/858)) ([d5c65a9](https://github.com/device-management-toolkit/rpc-go/commit/d5c65a90f9be865ced9bb8a66fe8dd9cf4d0d02e))

## [2.47.1](https://github.com/device-management-toolkit/rpc-go/compare/v2.47.0...v2.47.1) (2025-05-16)


### Bug Fixes

* add commit for ccm SHBC ([fc184d3](https://github.com/device-management-toolkit/rpc-go/commit/fc184d32848d646579253e5262b1f1469b122602))

# [2.47.0](https://github.com/device-management-toolkit/rpc-go/compare/v2.46.1...v2.47.0) (2025-05-15)


### Features

* adds support for secure host based configuration ([4e7753e](https://github.com/device-management-toolkit/rpc-go/commit/4e7753e660f6d0efb7e37d351fbfe2aeed999422)), closes [#797](https://github.com/device-management-toolkit/rpc-go/issues/797)

## [2.46.1](https://github.com/device-management-toolkit/rpc-go/compare/v2.46.0...v2.46.1) (2025-04-09)


### Bug Fixes

* updates CCM AMT features except user consent ([53b5ade](https://github.com/device-management-toolkit/rpc-go/commit/53b5ade262e2899fa5ef0c531a9fa4fb45911fa2))

# [2.46.0](https://github.com/device-management-toolkit/rpc-go/compare/v2.45.1...v2.46.0) (2025-04-09)


### Features

* enable local cira configuration ([6d0d648](https://github.com/device-management-toolkit/rpc-go/commit/6d0d648749300c5074bc627adbef07c505f35e98))

## [2.45.1](https://github.com/device-management-toolkit/rpc-go/compare/v2.45.0...v2.45.1) (2025-03-25)


### Bug Fixes

* prevent partial unprovision in CCM (only allow in ACM) ([afb7112](https://github.com/device-management-toolkit/rpc-go/commit/afb71120d2adceba8d910041c0d66ccd1b683727))

# [2.45.0](https://github.com/device-management-toolkit/rpc-go/compare/v2.44.0...v2.45.0) (2025-03-24)


### Features

* adds support for partial unprovisioning ([a78f092](https://github.com/device-management-toolkit/rpc-go/commit/a78f0925f9f9cae182f899fd43c2c98860350589)), closes [#781](https://github.com/device-management-toolkit/rpc-go/issues/781)

# [2.44.0](https://github.com/device-management-toolkit/rpc-go/compare/v2.43.1...v2.44.0) (2025-03-19)


### Features

* add -all flag to list all amtinfo including cert hashes ([db702c0](https://github.com/device-management-toolkit/rpc-go/commit/db702c0caf9611bb674e449bb5d69f24b872757b))

## [2.43.1](https://github.com/device-management-toolkit/rpc-go/compare/v2.43.0...v2.43.1) (2025-03-11)


### Bug Fixes

* license generation ([#777](https://github.com/device-management-toolkit/rpc-go/issues/777)) ([5b914fa](https://github.com/device-management-toolkit/rpc-go/commit/5b914faf758be6d20e5bd65e55511b95b6c08caf))
* license generation ([#778](https://github.com/device-management-toolkit/rpc-go/issues/778)) ([8ba6993](https://github.com/device-management-toolkit/rpc-go/commit/8ba6993074b9629b55c845f6cd05204a9e078ce9))
* update go mod ([8a1e741](https://github.com/device-management-toolkit/rpc-go/commit/8a1e7419f905abb6520a1898a2a6e5abbb8aab8a))

# [2.43.0](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.42.8...v2.43.0) (2025-02-10)


### Features

* ccm on tls only platforms ([#745](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/745)) ([80853ee](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/80853ee033e4370590e929ba2b6bd80cf092c6f0))

## [2.42.8](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.42.7...v2.42.8) (2025-01-15)


### Bug Fixes

* test ci ([8c5b3dd](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/8c5b3ddec5b3c8678fba93475675081aee99d8bb)) .
* test ci ([db52045](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/db52045bc8c7de7f9c7496d88edeca5ec4491ee0))

## [2.42.7](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.42.6...v2.42.7) (2025-01-15)


### Bug Fixes

* Use OS DNS suffix when DNS suffix set in MEBx is empty-like ([e89fd98](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/e89fd984915f998d5dd824bea04d84999b27a847))

## [2.42.6](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.42.5...v2.42.6) (2024-12-16)


### Bug Fixes

* opstate on amt 11 and below ([954f3d3](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/954f3d36bdd2fa076293536758772c492034aeba))

## [2.42.5](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.42.4...v2.42.5) (2024-11-15)

## [2.42.4](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.42.3...v2.42.4) (2024-11-15)

## [2.42.3](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.42.2...v2.42.3) (2024-11-15)

## [2.42.2](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.42.1...v2.42.2) (2024-11-14)


### Bug Fixes

* activates in ccm mode now ([a50f3a0](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/a50f3a0a4aef76bec2dbe949daabf16c02a7cbb8))

## [2.42.1](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.42.0...v2.42.1) (2024-11-14)

# [2.42.0](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.41.0...v2.42.0) (2024-11-06)


### Features

* IsWirelessSynchronized is optional in wireless configuration ([0847817](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/0847817d4bdb53751429a957d3b619a665a4fe01))

# [2.41.0](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.40.1...v2.41.0) (2024-11-05).


### Features

* enable config v2 from console ([a765f4c](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/a765f4c2c279f6fcb511d48cbca8be02e2762758))

## [2.40.1](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.40.0...v2.40.1) (2024-10-31)


### Bug Fixes

* add error handling when TLS activation is enforced ([#678](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/678)) ([f538952](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/f538952de54239ba092e281a40e7dbbdb5c3029f))

# [2.40.0](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.39.0...v2.40.0) (2024-10-15).


### Features

* generate third party licenses zip for every release ([#665](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/665)) ([10d7724](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/10d772492318060b70834974aa3df1476946fff6))

# [2.39.0](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.38.0...v2.39.0) (2024-09-17)


### Features

* lib.go redirects stdout to Output ([#640](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/640)) ([8697c99](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/8697c995f28e27631d26be291d711abdec1ad86d))

# [2.38.0](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.37.0...v2.38.0) (2024-09-05)


### Features

* adds ccm activation using config ([abd02bc](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/abd02bcbb05b88e44378c81962f8b89bf115327a))

# [2.37.0](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.36.2...v2.37.0) (2024-08-07)


### Features

* prunes wired and tls configs when adding new ones ([93553d2](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/93553d244543490b6e534a520bb1f3c1dd391ad3))

## [2.36.2](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.36.1...v2.36.2) (2024-08-06).


### Bug Fixes

* **cli:** Resolve FQDN on Linux machines with short hostnames ([#600](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/600)) ([a2df614](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/a2df61462461028ce32e0270029bb54a725f66af)), closes [#189](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/189)

## [2.36.1](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.36.0...v2.36.1) (2024-07-17)


### Bug Fixes

* attempt to address false positive virus on zipped go binary artifacts on windows ([#591](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/591)) ([6957954](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/695795411e30615e4206efc8945abaa9ce2ce22d))

# [2.36.0](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.35.0...v2.36.0) (2024-07-15)


### Features

* **cli:** amtinfo command add amt ipaddr and osipaddr ([#560](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/560)) ([77b42aa](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/77b42aad1f7b95e546eb17640f7981933a5bf999)), closes [#467](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/467)

# [2.35.0](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.34.2...v2.35.0) (2024-06-20)


### Features

* enable local commands without lms ([#486](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/486)) ([8b7e7b1](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/8b7e7b1bad73aa903a1e11294e78831d07c8fb45))

## [2.34.2](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.34.1...v2.34.2) (2024-06-05)


### Bug Fixes

* resolves close call issue in go-wsman-messages ([#550](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/550)) ([af9ffdb](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/af9ffdb9e1faae44a876346b9e08e67fb88e08b4))

## [2.34.1](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.34.0...v2.34.1) (2024-05-08)


### Bug Fixes

* add delay when processing multiple wireless profiles ([#510](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/510)) ([353af73](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/353af731b6127e2ede460e31706a382774ddc871))

# [2.34.0](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.33.1...v2.34.0) (2024-05-03)


### Features

* add yaml support to local tls config ([8ecb612](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/8ecb61257d6242f9d3d9467944482df58c27bd73))

## [2.33.1](https://github.com/open-amt-cloud-toolkit/rpc-go/compare/v2.33.0...v2.33.1) (2024-04-25)


### Bug Fixes

* 8021x wifi config with preexisting root cert ([55cc329](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/55cc32939313b8709c5f4b3d86bb1cfb1dc9e79e))
* **deps:** update to fixed go-wsman-messages to support 32-bit ([#500](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/500)) ([2640a12](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/2640a129e0b999ad531883204ad9663fac7b4a00))
* return value on success in lib.go ([#499](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/499)) ([ea30d19](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/ea30d196fc51ed06501dc46b8dca09f9947037bb))
* use go-wsman-messages v2.2.4 ([e2e568f](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/e2e568fa1f57b40b943283670396a4c1987c05ff))

<a name="v2.33.0"></a>
## [v2.33.0] - 2024-04-17
### Bug Fixes
* wifi prune ([#482](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/482)) ([0e2ce20](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/0e2ce200d0f4c37d22f843cb4328d1b597b2635a))

### Features
* adds 8021x to wired configuration ([1e34d85](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/1e34d852d980fa0c243dd101ec57b6211175b9cf))

<a name="v2.32.2"></a>
## [v2.32.2] - 2024-04-10
### Bug Fixes
- read ccm password from commandline ([5a83d49](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/5a83d49aebe1b089cb8de4f33c928b2d45efa28a))

<a name="v2.32.1"></a>
## [v2.32.1] - 2024-04-08
### Bug Fixes
- changed optin all type ([47ba85f](https://github.com/open-amt-cloud-toolkit/rpc-go/commit/47ba85f30dfec6e6648c1a198e77b7fbd179eeeb))

<a name="v2.31.2"></a>
## [v2.31.2] - 2024-04-04
### Build
- **deps:** bump codecov/codecov-action from 4.1.1 to 4.2.0 ([#465](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/465)) 
- **deps:** bump golang from 0466223 to cdc86d9 ([#464](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/464))
- **deps:** bump wagoid/commitlint-github-action from 5.4.5 to 6.0.0 ([#457](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/457))
- **deps:** deps: bump github.com/device-management-toolkit/go-wsman-messages/v2 from 2.2.0 to 2.2.2 
- **deps:** bump aquasecurity/trivy-action from 0.18.0 to 0.19.0
- **deps:** bump actions/add-to-project from 0.6.1 to 1.0.0
- **deps:** bump codecov/codecov-action from 4.1.0 to 4.1.1
- **deps:** bump github.com/device-management-toolkit/go-wsman-messages/v2 from 2.1.11 to 2.2.0 ([#446](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/446))
- **deps:** bump github/codeql-action from 3.24.8 to 3.24.9 ([#448](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/448))
- **deps:** bump actions/add-to-project from 0.6.0 to 0.6.1 ([#445](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/445))
- **deps:** bump cycjimmy/semantic-release-action from 4.0.0 to 4.1.0 ([#444](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/444))
- **deps:** bump github/codeql-action from 3.24.7 to 3.24.8 ([#439](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/439))
- **deps:** bump golang from fc5e584 to 0466223 ([#438](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/438))

### Ci
- addresses permissions for trivy-scan to upload ([#447](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/447))

### Docs
- update badge links
- update badge styles

### Feat
- adds configure amtpassword local command ([#442](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/442)) 
- adds amt features configuration ([#407](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/407)) 

### Fix
- use tm2 for SetHighAccuracyTimeSynch ([#460](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/460)) 
- removes duplicate printing for -h and -help flags on maintenance commands
- configure error code
- variable names for configJson input ([#441](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/441))

### Refractor
- adds wireless and wired subcommands deprecating addwifisettings and wiredsettings ([#461](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/461)) 

<a name="v2.29.1"></a>
## [v2.29.1] - 2024-03-15
### Build
- **deps:** bump github.com/device-management-toolkit/go-wsman-messages/v2 from 2.1.10 to 2.1.11
- **deps:** bump docker/login-action from 3.0.0 to 3.1.0 

### Docs
- adds copyright headers

### Fix
- local acm activate does not prompt for password when it is in the config ([#436](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/436)) 

<a name="v2.29.0"></a>
## [v2.29.0] - 2024-03-14
### Build
- **deps:** bump github.com/device-management-toolkit/go-wsman-messages/v2 from 2.1.9 to 2.1.10

### Feat
- adds addwiredsettings local configuration command ([#422](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/422)) 

<a name="v2.28.3"></a>
## [v2.28.3] - 2024-03-13
### Fix
- XML messages are no longer escaped when using -json flag ([#429](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/429)) 

<a name="v2.28.2"></a>
## [v2.28.2] - 2024-03-13
### Build
- **deps:** bump actions/checkout from 4.1.1 to 4.1.2 ([#423](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/423)) 
- **deps:** bump github/codeql-action from 3.24.6 to 3.24.7 ([#424](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/424)) 
- **deps:** bump github.com/device-management-toolkit/go-wsman-messages/v2 from 2.1.8 to 2.1.9

### Fix
- changes amtinfo output to use stdout instead of stderr

<a name="v2.28.1"></a>
## [v2.28.1] - 2024-03-13
### Build
- **deps:** bump golang from 8e96e6c to fc5e584 ([#414](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/414))
- **deps:** bump github.com/device-management-toolkit/go-wsman-messages/v2 from 2.1.7 to 2.1.8

### Ci
- adds changelog plugin to release

### Fix
- generated binaries should not use CGO ([#426](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/426))

<a name="v2.28.0"></a>
## [v2.28.0] - 2024-03-07
### Feat
- prompts for password in local activate and configure mebx ([#415](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/415))

<a name="v2.27.4"></a>
## [v2.27.4] - 2024-03-07
### Build
- **deps:** bump golang.org/x/term from 0.17.0 to 0.18.0 ([#410](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/410))
- **deps:** bump github/stretchr/testify from 1.8.4 to 1.9.0 ([#409](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/409))

### Fix
- local acm activate properly orders certificate chain

<a name="v2.27.3"></a>
## [v2.27.3] - 2024-03-05
### Build
- **deps:** bump golang.org/x/sys from 0.17.0 to 0.18.0 ([#411](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/411))

### Fix
- typo "AMT is already enabled" ([#412](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/412))

<a name="v2.27.2"></a>
## [v2.27.2] - 2024-03-04
### Fix
- local acm activation

<a name="v2.27.1"></a>
## [v2.27.1] - 2024-03-04
### Build
- **deps:** bump aquasecurity/trivy-action from 0.17.0 to 0.18.0
- **deps:** bump github/codeql-action from 3.24.5 to 3.24.6 ([#408](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/408))

### Fix
- password read on prompt

<a name="v2.27.0"></a>
## [v2.27.0] - 2024-02-28
### Build
- **deps:** bump github.com/device-management-toolkit/go-wsman-messages/v2 from 2.1.5 to 2.1.6 
- **deps:** bump github/codeql-action from 3.24.1 to 3.24.3
- **deps:** bump github.com/device-management-toolkit/go-wsman-messages/v2 from 2.1.6 to 2.1.7
- **deps:** bump codecov/codecov-action from 4.0.1 to 4.0.2
- **deps:** bump github/codeql-action from 3.24.3 to 3.24.5
- **deps:** bump codecov/codecov-action from 4.0.2 to 4.1.0
- **deps:** bump actions/addd-to-project from 0.5.0 to 0.6.0

### Feat
- adds tls configuration with signed certificate 

<a name="v2.26.2"></a>
## [v2.26.2] - 2024-02-15
### Fix
- inject version upon release in CI ([#389](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/389))

<a name="v2.26.1"></a>
## [v2.26.1] - 2024-02-15
### Fix
- update version to v2.26.1 ([#388](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/388))

<a name="v2.26.0"></a>
## [v2.26.0] - 2024-02-14
### Build
- **gh-actions:** upgrade build flags for executable
- **deps:** bump github.com/device-management-toolkit/go-wsman-messages/v2 from 2.1.4 to 2.1.5
- **deps:** bump golang.org/x/term from 0.16.0 to 0.17.0 ([#383](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/383))
- **deps:** bump github/codeql-action from 3.24.0 to 3.24.1 

### Ci
- remove azure boards sync ([#387](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/387))

### Fix
- read AMT and SMB passwords without terminal echo unless requested ([#357](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/357))
- check error upon getting lan interface settings ([#386](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/386))

### Feat
- adds an option to sync clock locally

### Refractor
- adds unit test to tls
- migrate apf to use go-wsman-messages ([#382](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/382))

<a name="v2.25.3"></a>
## [v2.25.3] - 2024-02-09
### Build
- **deps:** update go-wsman-messages v2.1.4 ([#378](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/378))

### Fix
- test executable flows for githubrelease ([#377](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/377))

<a name="v2.25.2"></a>
## [v2.25.2] - 2024-02-09
### Build
- **deps:** bump github.com/google/uuid from 1.4.0 to 1.6.0 ([#374](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/374))
- **deps:** bump github.com/open-amt-cloud-toolkit
- **deps:** bump golang from 1.21-alpine to 1.22-alpine ([#367](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/367))

### Ci
- add executables to artifact

### Fix
- this releases rpc-go with go-wsman-messages v2.1.3 ([#376](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/376))

<a name="v2.25.1"></a>
## [v2.25.1] - 2024-02-08
### Build
- bump go-wsman-messages to v2.0 ([#360](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/360))
- **deps:** bump golang.org/x/sys from 0.16.0 to 0.17.0 ([#368](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/368))
- **deps:** bump actions/upload-artifact from 4.3.0 to 4.3.1
- **deps:** bump aquasecurity/trivy-action from 0.16.1 to 0.17.0
- **deps:** bump github/codeql-action from 3.23.2 to 3.24.0 ([#356](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/356))
- **deps:** bump codecov/codecov-action from 4.0.0 to 4.0.1
- **deps:** bump codecov/codecov-action from 3.1.6 to 4.0.0
- **deps:** bump codecov/codecov-action from 3.1.5 to 3.1.6
- **deps:** bump step-security/harden-runner from 2.6.1 to 2.7.0
- **deps:** bump github/codeql-action from 3.23.1 to 3.23.2
- **deps:** bump golang from `51a7800` to `a6a7f1f`
- **deps:** bump codecov/codecov-action from 3.1.4 to 3.1.5
- **deps:** bump golang from `fd78f2f` to `51a7800`
- **deps:** bump actions/upload-artifact from 4.2.0 to 4.3.0

### Ci
- pin version of config [@commitlint](https://github.com/commitlint)/config-conventional to 18.5

### Docs
- correct tls help example command

### Fix
- update build tasks and project version

<a name="v2.25.0"></a>
## [v2.25.0] - 2024-01-23
### Build
- **deps:** bump actions/upload-artifact from 4.1.0 to 4.2.0
- **deps:** bump github/codeql-action from 3.23.0 to 3.23.1
- **deps:** bump actions/upload-artifact from 4.0.0 to 4.1.0
- **deps:** bump golang from `4db4aac` to `fd78f2f`

### Feat
- add local self-signed tls configuration

### Refactor
- added logging for transactions for local activation
- **internal:** removes logging at trace level

<a name="v2.24.4"></a>
## [v2.24.4] - 2024-01-09
### Build
- **deps:** bump wagoid/commitlint-github-action from 5.4.4 to 5.4.5
- **deps:** bump github/codeql-action from 3.22.12 to 3.23.0
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages
- **deps:** bump golang.org/x/sys from 0.15.0 to 0.16.0
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages
- **deps:** bump aquasecurity/trivy-action from 0.16.0 to 0.16.1

### Fix
- update project version

<a name="v2.24.3"></a>
## [v2.24.3] - 2023-12-28
### Build
- **deps:** bump github/codeql-action from 3.22.11 to 3.22.12
- **deps:** bump golang from `feceecc` to `4db4aac`
- **deps:** bump golang.org/x/crypto from 0.14.0 to 0.17.0
- **deps:** bump actions/upload-artifact from 3.1.3 to 4.0.0
- **deps:** bump github/codeql-action from 2.22.10 to 3.22.11
- **deps:** bump github/codeql-action from 2.22.9 to 2.22.10
- **deps:** bump golang from `5c1cabd` to `feceecc`
- **deps:** bump aquasecurity/trivy-action from 0.15.0 to 0.16.0
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages
- **deps:** bump github/codeql-action from 2.22.8 to 2.22.9
- **deps:** bump golang from `70afe55` to `5c1cabd`

### Ci
- add trivy results to github security tab

### Fix
- makes sure uuid flag warning is only shown when the flag is used

<a name="v2.24.2"></a>
## [v2.24.2] - 2023-12-05
### Build
- **deps:** bump golang from `30a46e7` to `70afe55`
- **deps:** bump actions/setup-dotnet from 3.2.0 to 4.0.0
- **deps:** bump aquasecurity/trivy-action from 0.14.0 to 0.15.0
- **deps:** bump golang from `110b07a` to `30a46e7`

### Fix
- local activation supports .pfx

<a name="v2.24.1"></a>
## [v2.24.1] - 2023-11-29
### Fix
- project version is updated

<a name="v2.24.0"></a>
## [v2.24.0] - 2023-11-29
### Build
- **deps:** bump golang.org/x/sys from 0.14.0 to 0.15.0

### Feat
- add UUID Override flag to maintenance commands

<a name="v2.23.0"></a>
## [v2.23.0] - 2023-11-27
### Build
- **deps:** bump github/codeql-action from 2.22.7 to 2.22.8
- **deps:** bump github/codeql-action from 2.22.6 to 2.22.7
- **deps:** bump step-security/harden-runner from 2.6.0 to 2.6.1
- **deps:** bump github/codeql-action from 2.22.5 to 2.22.6
- **deps:** bump golang from `96a8a70` to `110b07a`
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages

### Feat
- support AMTEnabled flag

<a name="v2.22.0"></a>
## [v2.22.0] - 2023-11-07
### Build
- **deps:** bump aquasecurity/trivy-action from 0.13.1 to 0.14.0

### Feat
- adds report out to code analysis action

<a name="v2.21.0"></a>
## [v2.21.0] - 2023-11-06
### Build
- **deps:** bump golang.org/x/sys from 0.13.0 to 0.14.0
- **deps:** bump github.com/gorilla/websocket from 1.5.0 to 1.5.1
- **deps:** bump software.sslmate.com/src/go-pkcs12 from 0.3.0 to 0.4.0
- **deps:** bump aquasecurity/trivy-action from 0.13.0 to 0.13.1
- **deps:** bump wagoid/commitlint-github-action from 5.4.3 to 5.4.4
- **deps:** bump golang from `926f7f7` to `96a8a70`

### Feat
- support smb: urls for remote .yaml or .pfx config files

<a name="v2.20.0"></a>
## [v2.20.0] - 2023-11-01
### Feat
- add local wifi enable and profile sync

<a name="v2.19.0"></a>
## [v2.19.0] - 2023-10-30
### Build
- **deps:** bump github/codeql-action from 2.22.4 to 2.22.5
- **deps:** bump software.sslmate.com/src/go-pkcs12 from 0.2.1 to 0.3.0

### Feat
- local operations read secrets from environment

<a name="v2.18.0"></a>
## [v2.18.0] - 2023-10-26
### Build
- **deps:** bump aquasecurity/trivy-action from 0.12.0 to 0.13.0
- **deps:** bump ossf/scorecard-action from 2.3.0 to 2.3.1
- **deps:** bump github/codeql-action from 2.22.3 to 2.22.4
- **deps:** bump actions/checkout from 4.1.0 to 4.1.1
- **deps:** bump github/codeql-action from 2.22.2 to 2.22.3

### Feat
- add device info maintenance

<a name="v2.17.0"></a>
## [v2.17.0] - 2023-10-13
### Build
- **deps:** bump github/codeql-action from 2.22.1 to 2.22.2

### Feat
- add features field to message payload

<a name="v2.16.1"></a>
## [v2.16.1] - 2023-10-12
### Build
- removes jenkinsfile
- **deps:** bump golang from `a76f153` to `926f7f7`
- **deps:** bump ossf/scorecard-action from 2.2.0 to 2.3.0
- **deps:** bump github/codeql-action from 2.21.9 to 2.22.0
- **deps:** bump golang from `1c9cc94` to `a76f153`
- **deps:** bump golang.org/x/sys from 0.12.0 to 0.13.0
- **deps:** bump golang from `4bc6541` to `1c9cc94`
- **deps:** bump step-security/harden-runner from 2.5.1 to 2.6.0
- **deps:** bump github/codeql-action from 2.22.0 to 2.22.1
- **deps:** bump golang from `ec31b7f` to `4bc6541`
- **deps:** bump github/codeql-action from 2.21.8 to 2.21.9
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages ([#240](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/240))
- **deps:** bump golang from `96634e5` to `ec31b7f`

### Ci
- only release when semantic-release generates a new version
- automate publishing of docker images to dockerhub

### Fix
- update ProjectVersion to v2.16.1

<a name="v2.16.0"></a>
## [v2.16.0] - 2023-09-26
### Build
- **deps:** bump actions/checkout from 4.0.0 to 4.1.0

### Feat
- adds uuid flag to activate command

<a name="v2.15.2"></a>
## [v2.15.2] - 2023-09-20
### Build
- **deps:** bump github/codeql-action from 2.21.7 to 2.21.8
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages

### Ci
- update docker release

### Fix
- trigger ci build for release with docker

### Refactor
- amtinfo userCert password prompt ([#228](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/228))

<a name="v2.15.1"></a>
## [v2.15.1] - 2023-09-15
### Build
- **deps:** bump github/codeql-action from 2.21.6 to 2.21.7
- **deps:** bump github/codeql-action from 2.21.5 to 2.21.6

### Ci
- add semantic-release-docker plugin
- adds exec plugin for [@semantic](https://github.com/semantic)-release

### Docs
- config file names and comments

### Fix
- add prompt for password acm local deactivation
- addwifisettings validate unique priorities

### Refactor
- config file names and comments

<a name="v2.15.0"></a>
## [v2.15.0] - 2023-09-13
### Build
- **deps:** bump docker/login-action from 2.2.0 to 3.0.0
- **deps:** bump golang from `445f340` to `96634e5`
- **deps:** bump actions/upload-artifact from 3.1.2 to 3.1.3
- **deps:** bump golang.org/x/sys from 0.11.0 to 0.12.0

### Ci
- add release tag to docker image

### Docs
- update badges

### Feat
- amtinfo display user certificates

### Refactor
- **utils:** creates type for return codes and makes variable names consistent ([#212](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/212))

<a name="v2.14.2"></a>
## [v2.14.2] - 2023-09-08
### Fix
- ensure warning for CCM deactivation password flag

<a name="v2.14.1"></a>
## [v2.14.1] - 2023-09-06
### Fix
- addwifisettings - track added certs to prevent duplicates error

<a name="v2.14.0"></a>
## [v2.14.0] - 2023-09-06
### Build
- bump go-wsman-messages to v1.8.2 ([#205](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/205))
- **deps:** bump actions/checkout from 3.6.0 to 4.0.0
- **deps:** bump aquasecurity/trivy-action
- **deps:** bump go-wsman-messages to v1.8.1
- **deps:** bump cycjimmy/semantic-release-action from 3.4.2 to 4.0.0
- **deps:** bump github/codeql-action from 2.21.4 to 2.21.5
- **deps:** bump actions/checkout from 3.5.3 to 3.6.0

### Feat
- local wifi configuration

<a name="v2.13.1"></a>
## [v2.13.1] - 2023-08-16
### Build
- **deps:** bump github/codeql-action from 2.21.3 to 2.21.4
- **deps:** bump docker/login-action from 1.6.0 to 2.2.0

### Ci
- push another image with a github tag

### Fix
- update ProjectVersion to 2.13.0

<a name="v2.13.0"></a>
## [v2.13.0] - 2023-08-14
### Build
- **deps:** bump github/codeql-action from 1.1.39 to 2.21.3
- **deps:** bump step-security/harden-runner from 2.5.0 to 2.5.1
- **deps:** bump aquasecurity/trivy-action
- **deps:** bump codecov/codecov-action from 3.1.3 to 3.1.4
- **deps:** bump golang.org/x/sys from 0.10.0 to 0.11.0
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages
- **deps:** bump actions/upload-artifact from 2.3.1 to 3.1.2
- **deps:** bump golang from 1.20-alpine to 1.21-alpine
- **deps:** bump actions/checkout from 3.1.0 to 3.5.3
- **deps:** bump actions/setup-dotnet from 2.1.1 to 3.2.0
- **deps:** bump danhellem/github-actions-issue-to-work-item
- **deps:** bump wagoid/commitlint-github-action from 4.1.15 to 5.4.3
- **deps:** bump actions/add-to-project from 0.3.0 to 0.5.0
- **deps:** bump ossf/scorecard-action from 2.0.6 to 2.2.0

### Ci
- [StepSecurity] Apply security best practices
- adds release notes generator and github to semantic release

### Feat
- activate in acm using local command

### Refactor
- result codes ([#185](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/185))
- add configure command

<a name="v2.12.0"></a>
## [v2.12.0] - 2023-07-27
### Build
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages
- **deps:** bump github.com/ilyakaznacheev/cleanenv from 1.4.2 to 1.5.0

### Feat
- add local deactivation in ACM

### Refactor
- move command execution out of flags package

<a name="v2.11.1"></a>
## [v2.11.0] - 2023-07-14
### Fix
- password not set correctly for ccm activate

### Refactor
- **internal:** remove .parsed check

<a name="v2.11.0"></a>
## [v2.11.0] - 2023-07-10
### Build
- update version to v2.11.0
- **deps:** bump golang.org/x/sys from 0.9.0 to 0.10.0
- **deps:** bump github.com/open-amt-cloud-toolkit/go-wsman-messages
- **deps:** bump golang.org/x/sys from 0.8.0 to 0.9.0

### Ci
- added semantic release

### Feat
- add local CCM activate

### Fix
- allow for spaces in input parameters

### Refactor
- simplify friendly name

<a name="v2.10.0"></a>
## [v2.10.0] - 2023-06-16
### Build
- update version and changelog to v2.10.0

### Feat
- adds AMT Features to amtinfo
- support device friendly name

<a name="v2.9.1"></a>
## [v2.9.1] - 2023-06-08
### Build
- update version and changelog to v2.9.1
- **deps:** bump github.com/sirupsen/logrus from 1.9.2 to 1.9.3
- **deps:** bump github.com/stretchr/testify from 1.8.3 to 1.8.4

### Fix
- **internal:** GetOSDnsSuffixOS bug with docker desktop

<a name="v2.9.0"></a>
## [v2.9.0] - 2023-05-25
### Build
- update version and changelog for v2.9.0
- **deps:** bump github.com/stretchr/testify from 1.8.2 to 1.8.3

### Ci
- add trivy container scan

### Feat
- **cli:** addwifisettings directly without cloud interaction

### Refactor
- **internal:** move each command to its own file

### Test
- move flag tests to respective files for better organization

<a name="v2.8.0"></a>
## [v2.8.0] - 2023-05-18
### Build
- update version to 2.8.0 and changelog
- add tasks.json for vscode
- add launch.json to gitignore
- add various command templates for easy debugging in VSCode
- **deps:** bump github.com/sirupsen/logrus from 1.9.1 to 1.9.2 ([#129](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/129))
- **deps:** bump github.com/sirupsen/logrus from 1.9.0 to 1.9.1 ([#127](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/127))

### Feat
- deactivate a device in CCM from RPC

<a name="v2.7.0"></a>
## [v2.7.0] - 2023-05-04
### Build
- update version to 2.7.0, update changelogbuild: update version to 2.6.0, update changelog
- update go to 1.20
- **deps:** bump golang.org/x/sys from 0.5.0 to 0.6.0
- **deps:** bump github.com/stretchr/testify from 1.8.1 to 1.8.2
- **deps:** bump github.com/gorilla/websocket from 1.4.2 to 1.5.0
- **deps:** bump github.com/sirupsen/logrus from 1.7.0 to 1.9.0
- **deps:** bump github.com/stretchr/testify from 1.7.0 to 1.8.1
- **deps:** bump golang.org/x/sys from 0.3.0 to 0.5.0

### Ci
- add go fmt and format code
- update github runners
- adds dependabot config
- **deps:** bump codecov to 3.1.3 ([#119](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/119))

### Docs
- add discord info ([#111](https://github.com/open-amt-cloud-toolkit/rpc-go/issues/111))

### Feat
- **utils:** add -f (force) flag

### Fix
- **rps:** rpc will exit instead of hang when connection fails to rps

<a name="v2.6.0"></a>
## [v2.6.0] - 2023-02-16
### Build
- update version to 2.6.0, update changelog
- **docker:** update golang base to 1.19

### Ci
- set os to 18.04
- fix changelog job
- add ossf action

### Docs
- align format to match other repositories
- add ossf badge to readme

### Feat
- added flag tenantId
- **rps:** added proxy support

### Fix
- proper processing of command line flags

### Refactor
- adds new return codes

<a name="v2.5.0"></a>
## [v2.5.0] - 2022-12-08
### Build
- update version to 2.5.0, update changelog

### Ci
- pin .net core build
- update actions/checkout to v3, update semantic
- add azure board sync
- add project sync to rpc-go

### Feat
- **AMTtimeout:** Handle wait if AMT is not ready
- **cli:** sync hostname

### Refactor
- update log messages to be a bit more clear

<a name="v2.4.0"></a>
## [v2.4.0] - 2022-11-07

### Build
- bump to v2.4.0

### Feat
- **maintenance:** add subcommands for syncip, syncclock, and changepassword

### Fix
- channel recipient channel should not be 0
- remove extra log.error statement


<a name="v2.3.0"></a>
## v2.3.0 - 2022-10-05

### Ci
- add junit test output

### Docs
- update changelog for v2.3.0

### Feat
- add warnings for link status and dns suffix
- added admin privilege check and AMT not found error check
- **amtinfo:** display wired only when wired adapter is available
- **win:** add admin privilege check

### Fix
- **amtinfo:** shouldnt display warnings on amtinfo
- **tls:** tls configuration now completes after TLS configuration

### Refactor
- **return codes:** replace log.Fatal with log.Error replace os.Exit calls
- **return-codes:** change tag error handling to continue instead of exit
- **status:** attempt to unmarshal error message

<a name="v2.2.0"></a>
## [v2.2.0] - 2022-05-09

### Build
- **version:** bump to v2.2.00

### Ci
- add build for sample
- **docker:** ensure docker build occurs in PR checks
- **lint:** adds semantic checks to PRs

### Docs
- **changelog:** update version
- **readme:** add command for shared library build
- **readme:** remove unnecessary prerequisites

### Feat
- **build:** adds support for c-shared buildmode
- **logging:** adds support for fine grained control of log ouput

### Fix
- **heci:** adds retry for device busy

### Refactor
- **lms:** rewrite lme communication in go
- **main:** eliminate need for CGO if not buildling library

## [v2.1.0] - 2022-03-18
### Build
- **docker:** C style comments are not valid in Dockerfiles
- **version:** update version to v2.1.0

### Ci
- **jenkinsfile:** removes protex scan
- **workflow:** only uploads codecov for 20.04

### Docs
- **docker:** how to build and run using Docker

### Feat
- **activate:** prompts for password when device is activated
- **cli:** Remove ControlModeRaw from json
- **cli:** Add json flag to version command
- **log:** adds -json option to all rpc commands
- **output:** adds json output for amtinfo command

### Fix
- update password with user input

### Refactor
- **pthi:** converts amt and pthi commands to go from C

<a name="v2.0.0"></a>
## v2.0.0 - 2021-11-08
### Build
- **dockerfile:** adds license header

### Ci
- update default branch name to main for jobs
- add docker and changelog builds
- update codeql build command
- add codeql
- **jenkins:** create jenkinsfile

### Docs
- add contributing guidlines
- add license and security guidelines

### Feat
- add environment variable support
- add heartbeat support
- **hostname:** can now override hostname of device by passing -h as command line arg
- **maintenance:** add time sync for AMT
- **rpc:** initial commit

### Fix
- dns suffix and trim string outputs for commands
- **version:** add version output to cli command

### Refactor
- rename mps to rps for accurate naming
- **rpc:** organize code to be unit testable
