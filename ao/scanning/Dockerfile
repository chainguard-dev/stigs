FROM fedora:latest

# Update packages in a separate RUN command so that we don't have to keep rebuilding the image
RUN dnf update -y

# Install OpenSCAP scanner and SCAP Security Guide
RUN dnf install -y openscap-scanner scap-security-guide \
    && dnf clean all

# Set the working directory
WORKDIR /

# Default command to show help
CMD ["oscap", "--help"] 