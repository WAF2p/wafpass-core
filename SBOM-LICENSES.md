# Software Bill of Materials and License Overview

This document summarizes the software components used by **wafpass-core (pass)**
and their licenses. It is generated for CNCF submission readiness.

## Project metadata

- **Project:** wafpass-core (pass)
- **Own license:** Apache-2.0
- **License file present:** yes

## SBOM artifacts

Every build produces the following artifacts (uploaded to GitHub Actions):

- `sbom.cyclonedx.json` — CycloneDX 1.6 JSON
- `sbom.spdx.json` — SPDX 2.3 JSON
- `licenses.json` — License report (JSON)

Release builds also attach the CycloneDX and SPDX files to the GitHub release.

## Dependency summary

- **Total detected packages:** 26

### License distribution

| License | Count |
|---------|-------|
| MIT | 15 |
| BSD-3-Clause | 4 |
| Apache-2.0 | 2 |
| MPL-2.0 | 1 |
| MIT-0 | 1 |
| BSD-2-Clause | 1 |
| ISC | 1 |
| PSF-2.0 | 1 |

## Package list

| Package | Version | License |
|---------|---------|---------|
| annotated-doc | 0.0.5 | MIT |
| annotated-types | 0.8.0 | MIT |
| anyio | 4.15.1 | MIT |
| certifi | 2026.7.22 | MPL-2.0 OR License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0) |
| cffi | 2.1.1 | MIT-0 |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause |
| h11 | 0.16.0 | MIT |
| httpcore | 1.0.9 | BSD-3-Clause |
| httpx | 0.28.1 | BSD-3-Clause OR License :: OSI Approved :: BSD License |
| idna | 3.20 | BSD-3-Clause |
| lark | 1.3.1 | MIT |
| markdown-it-py | 4.2.0 | MIT |
| mdurl | 0.1.2 | MIT |
| pip | 26.2.1 | MIT |
| pycparser | 3.0 | BSD-3-Clause |
| pydantic | 2.13.5 | MIT |
| pydantic_core | 2.46.5 | MIT |
| Pygments | 2.21.0 | BSD-2-Clause |
| python-hcl2 | 8.1.4 | MIT |
| PyYAML | 6.0.3 | MIT |
| regex | 2026.9.29 | Apache-2.0 AND CNRI-Python |
| rich | 15.0.0 | MIT |
| shellingham | 1.5.4 | ISC |
| typer | 0.27.2 | MIT |
| typing-inspection | 0.4.4 | MIT |
| typing_extensions | 4.16.0 | PSF-2.0 |

---

*Generated automatically from SBOM and license scan data.*