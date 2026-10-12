# Third-party notices

Original project code is provided under the root Apache 2.0 license. Third-party
components retain their respective licenses; the root license does not replace them.

## Checkmarx CLI reference sources and runner binary

The reference sources in `api-mock/upstream/ast-cli/` come from
https://github.com/Checkmarx/ast-cli at the commit recorded in
`api-mock/upstream/manifest.json`. They are unmodified and include:

- [Apache 2.0 license and Checkmarx copyright notice](api-mock/upstream/ast-cli/LICENSE).
- [Upstream third-party notices](api-mock/upstream/ast-cli/THIRD_PARTY_LICENSES.txt).
- [Referenced BSD 3-Clause license](api-mock/upstream/ast-cli/licenses/github.com_alexbrainman_sspi_LICENSE).

The runner downloader packages these files alongside the pinned official CLI.
Both runner Dockerfiles install them in `/usr/share/licenses/checkmarx-cli/`.
Preserve the licenses, attribution and any applicable upstream NOTICE files when
redistributing or updating these components. Mark any future modifications to
vendored files as required by their license.

## Runtime dependencies and base images

Python packages, Debian/Python base images, WireMock and Swagger UI are separately
licensed upstream components. Their licenses continue to apply. This document
does not replace their notices or constitute a complete dependency license audit.

## Product names

This project is independent and is not affiliated with, endorsed by, or supported
by Checkmarx. References to Checkmarx identify the compatible product and upstream
source; no trademark license or endorsement is asserted.
