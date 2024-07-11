# stigs

## Overview

Chainguard has developed a STIG profile for images built with Wolfi, namely,
all Chainguard Images.  The profile is based on the General Purpose Operating
System (GPOS) STIG which defines hardening checks across a range of
capabilities including cryptography, remote access, and internal configuration.
The Chainguard GPOS STIG profile is compatible with common STIG checking tools
including OpenSCAP and SCAP Viewer - instructions for using those tools are
included below.

When the STIG profile is run against a Chainguard Image, the scanning tool will
check several aspects of the image's configuration based on which GPOS checks
apply to a container image.  An explanation of each check is included and those
checks marked as Not Applicable include a rationale section explaining why the
checks do not apply.  For more information on STIG scanning containers see
[DISA's Container Hardening
Whitepaper](https://dl.dod.cyber.mil/wp-content/uploads/devsecops/pdf/Final_DevSecOps_Enterprise_Container_Hardening_Guide_1.2.pdf)

## Getting Started

The simplest way to get started is to use Chainguard's pre-packaged Chainguard
Image for
[`openscap`](https://images.chainguard.dev/directory/image/openscap/overview),
which includes the `openscap` tool itself, the `oscap-docker` libraries, and
the Chainguard GPOS STIG profile. This image is built with the same
capabilities and low-to-zero CVEs as every other Chainguard image, and makes
the otherwise difficult to setup `openscap` tool portable.

The instructions below assume that `docker` is installed and running on your
system, and are intended to be performed on a non-production system, similar to
the process outlined in DISA's Container Hardening Whitepaper.

For ease of use, we'll use the datastream file sourced from this repository,
and available within Chainguard's openscap image, we'll refer to this as the
`scan` image, and the `target` image we'll be scanning will be:
`cgr.dev/chainguard/wolfi-base:latest`.

```bash
# Start the target image (required by openscap-docker)
docker run --name target -d cgr.dev/chainguard/wolfi-base:latest tail -f /dev/null

# Run the scan image against the target image
# NOTE: This is a highly privileged container since we're scanning a container being run by the host's docker daemon.
docker run -i --rm -u 0:0 --pid=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/out:/out \
  --entrypoint sh \
  cgr.dev/chainguard/openscap:latest-dev <<_END_DOCKER_RUN
oscap-docker container target xccdf eval \
  --profile "xccdf_basic_profile_.check" \
  --report /out/report.html \
  --results /out/results.xml \
  /usr/share/xml/scap/ssg/content/ssg-chainguard-gpos-ds.xml
_END_DOCKER_RUN
```

The results of the scan will be written to the current directory in the `out`
directory.  The `report.html` file will contain a human-readable report of the
scan results, and the `results.xml` file will contain the raw results of the
scan.

### Alternative Uses

The SSG content in this repository can be used by any other tool that supports
the format, such as SCAP Workbench. For an alternative walkthrough of using
SCAP workbench, see [alternative uses](./docs/alternatives.md).

## Updates

The Chainguard STIG profile is re-evaluated and evolves alongside Wolfi OS and
Chainguard images. New releases of the profile is marked by a new version
number. The `cgr.dev/chainguard/openscap:latest` image always contains the
latest version of the Chainguard GPOS profile.
