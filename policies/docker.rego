# Docker Security Policies
# These policies enforce security best practices for Dockerfiles

package docker

import rego.v1

# Base Image Security

deny contains msg if {
    input[i].Cmd == "from"
    val := input[i].Value
    contains(val[_], ":latest")
    msg := "Dockerfile must not use 'latest' tag for base images - specify explicit versions"
}

warn contains msg if {
    input[i].Cmd == "from"
    val := input[i].Value
    not contains(val[_], ":")
    msg := "Dockerfile should specify an explicit tag for base images"
}

# User Security

deny contains msg if {
    not has_user_instruction
    msg := "Dockerfile must include USER instruction to run as non-root user"
}

has_user_instruction if {
    input[_].Cmd == "user"
}

deny contains msg if {
    input[i].Cmd == "user"
    input[i].Value[_] == "root"
    msg := "Dockerfile must not run as root user"
}

deny contains msg if {
    input[i].Cmd == "user"
    input[i].Value[_] == "0"
    msg := "Dockerfile must not run as UID 0 (root)"
}

# Package Management

warn contains msg if {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    contains(lower(val), "apt-get install")
    not contains(lower(val), "--no-install-recommends")
    msg := "apt-get install should use --no-install-recommends to minimize image size"
}

warn contains msg if {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    contains(lower(val), "apt-get update")
    not contains(lower(val), "apt-get clean")
    msg := "apt-get update should be followed by apt-get clean to minimize image size"
}

deny contains msg if {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    contains(lower(val), "apt-get upgrade")
    msg := "Dockerfile should not run apt-get upgrade - use a newer base image instead"
}

# Secrets and Sensitive Data

deny contains msg if {
    input[i].Cmd == "env"
    val := lower(concat(" ", input[i].Value))
    contains(val, "password")
    msg := "Dockerfile must not contain hardcoded passwords in ENV instructions"
}

deny contains msg if {
    input[i].Cmd == "env"
    val := lower(concat(" ", input[i].Value))
    contains(val, "secret")
    msg := "Dockerfile must not contain hardcoded secrets in ENV instructions"
}

deny contains msg if {
    input[i].Cmd == "env"
    val := lower(concat(" ", input[i].Value))
    contains(val, "api_key")
    msg := "Dockerfile must not contain hardcoded API keys in ENV instructions"
}

deny contains msg if {
    input[i].Cmd == "env"
    val := lower(concat(" ", input[i].Value))
    contains(val, "token")
    msg := "Dockerfile must not contain hardcoded tokens in ENV instructions"
}

# Port Exposure

warn contains msg if {
    input[i].Cmd == "expose"
    val := input[i].Value[_]
    val == "22"
    msg := "Exposing SSH port 22 is not recommended for containers"
}

warn contains msg if {
    input[i].Cmd == "expose"
    val := input[i].Value[_]
    val == "3389"
    msg := "Exposing RDP port 3389 is not recommended for containers"
}

# HEALTHCHECK

warn contains msg if {
    not has_healthcheck
    msg := "Dockerfile should include HEALTHCHECK instruction for container health monitoring"
}

has_healthcheck if {
    input[_].Cmd == "healthcheck"
}

# ADD vs COPY

warn contains msg if {
    input[i].Cmd == "add"
    val := concat(" ", input[i].Value)
    not contains(val, "http://")
    not contains(val, "https://")
    not contains(val, ".tar")
    not contains(val, ".gz")
    msg := "Use COPY instead of ADD for files that don't require extraction or remote URLs"
}

# Image Minimization

warn contains msg if {
    count([x | input[x].Cmd == "run"]) > 10
    msg := "Consider combining RUN commands to reduce image layers and size"
}

# Security Best Practices

deny contains msg if {
    input[i].Cmd == "run"
    val := lower(concat(" ", input[i].Value))
    contains(val, "curl")
    contains(val, "bash")
    not contains(val, "rm")
    msg := "If downloading and executing scripts with curl, ensure temporary files are cleaned up"
}

warn contains msg if {
    input[i].Cmd == "run"
    val := lower(concat(" ", input[i].Value))
    contains(val, "sudo")
    msg := "Avoid using sudo in Dockerfiles - run commands as appropriate user or switch with USER"
}

# Metadata

warn contains msg if {
    not has_label_maintainer
    not has_label_authors
    msg := "Dockerfile should include LABEL with maintainer or authors information"
}

has_label_maintainer if {
    input[i].Cmd == "label"
    val := lower(concat(" ", input[i].Value))
    contains(val, "maintainer")
}

has_label_authors if {
    input[i].Cmd == "label"
    val := lower(concat(" ", input[i].Value))
    contains(val, "authors")
}

# Workdir

warn contains msg if {
    not has_workdir
    msg := "Dockerfile should use WORKDIR instead of 'RUN cd' commands"
}

has_workdir if {
    input[_].Cmd == "workdir"
}

deny contains msg if {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    startswith(trim_space(val), "cd ")
    msg := "Use WORKDIR instead of 'RUN cd' to change directories"
}
