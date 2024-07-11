# Alternative Uses

The SSG content in this repository can be used by any other tool that supports
the format. The sections below provide examples of using other tools.

## XCCDF Files

As an alternative to the datastream file, the XCCDF format is also supported. While they represent identical checks, the format may be preferable by certain tooling.

The XCCDF files are suffixed with `-xccdf` in the folder. For example, the GPOS profile is located at:

```
./gpos/xml/scap/ssg/content/ssg-chainguard-xccdf/ssg-chainguard-xccdf/
```

## SCAP Workbench

The following will walk through using SCAP Workbench alongside with GPOS Datastream file.

1. Clone the `chainguard-dev/stigs` repository

2. Navigate to the directory with the XCCDF files, by default this is:

```
./gpos/xml/scap/ssg/content/ssg-chainguard-xccdf/OvalChecks/
```

3. From that directory, load the content into SCAP Workbench by selecting `Other SCAP Content > Load Content`.

4. The GPOS content has a single profile, which when loaded into SCAP Workbench can be customized and saved as a Tailoring file.
