# Kubernetes Security Policies
# These policies enforce security best practices for Kubernetes manifests

package kubernetes

import rego.v1

# Container Security

deny contains msg if {
    input.kind == "Deployment"
    not input.spec.template.spec.securityContext
    msg := sprintf("Deployment '%s' must define a security context", [input.metadata.name])
}

deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod"]
    some container
    container := input.spec.template.spec.containers[container]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Container '%s' must run as non-root user (runAsNonRoot: true)", [container.name])
}

deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod"]
    some container
    container := input.spec.template.spec.containers[container]
    container.securityContext.privileged == true
    msg := sprintf("Container '%s' must not run in privileged mode", [container.name])
}

deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod"]
    some container
    container := input.spec.template.spec.containers[container]
    not container.securityContext.allowPrivilegeEscalation == false
    msg := sprintf("Container '%s' must set allowPrivilegeEscalation to false", [container.name])
}

deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod"]
    some container
    container := input.spec.template.spec.containers[container]
    not container.securityContext.readOnlyRootFilesystem
    msg := sprintf("Container '%s' should use a read-only root filesystem", [container.name])
}

# Resource Limits

deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet"]
    some container
    container := input.spec.template.spec.containers[container]
    not container.resources.limits.memory
    msg := sprintf("Container '%s' must have memory limits defined", [container.name])
}

deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet"]
    some container
    container := input.spec.template.spec.containers[container]
    not container.resources.limits.cpu
    msg := sprintf("Container '%s' must have CPU limits defined", [container.name])
}

warn contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet"]
    some container
    container := input.spec.template.spec.containers[container]
    not container.resources.requests.memory
    msg := sprintf("Container '%s' should have memory requests defined", [container.name])
}

warn contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet"]
    some container
    container := input.spec.template.spec.containers[container]
    not container.resources.requests.cpu
    msg := sprintf("Container '%s' should have CPU requests defined", [container.name])
}

# Image Security

deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod"]
    some container
    container := input.spec.template.spec.containers[container]
    endswith(container.image, ":latest")
    msg := sprintf("Container '%s' must not use 'latest' image tag", [container.name])
}

deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod"]
    some container
    container := input.spec.template.spec.containers[container]
    not contains(container.image, ":")
    msg := sprintf("Container '%s' must specify an explicit image tag", [container.name])
}

warn contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod"]
    some container
    container := input.spec.template.spec.containers[container]
    container.imagePullPolicy != "Always"
    msg := sprintf("Container '%s' should use imagePullPolicy: Always", [container.name])
}

# Network Policies

warn contains msg if {
    input.kind == "Namespace"
    not has_network_policy
    msg := sprintf("Namespace '%s' should have a NetworkPolicy defined", [input.metadata.name])
}

has_network_policy if {
    some policy
    input.items[policy].kind == "NetworkPolicy"
}

# Service Security

deny contains msg if {
    input.kind == "Service"
    input.spec.type == "LoadBalancer"
    not input.metadata.annotations["service.beta.kubernetes.io/aws-load-balancer-internal"]
    msg := sprintf("Service '%s' LoadBalancer should be internal unless explicitly required", [input.metadata.name])
}

warn contains msg if {
    input.kind == "Service"
    input.spec.type == "NodePort"
    msg := sprintf("Service '%s' uses NodePort - consider using ClusterIP or LoadBalancer", [input.metadata.name])
}

# RBAC Security

deny contains msg if {
    input.kind == "ClusterRoleBinding"
    input.subjects[_].name == "system:anonymous"
    msg := sprintf("ClusterRoleBinding '%s' must not bind to anonymous users", [input.metadata.name])
}

deny contains msg if {
    input.kind == "RoleBinding"
    input.subjects[_].name == "system:unauthenticated"
    msg := sprintf("RoleBinding '%s' must not bind to unauthenticated users", [input.metadata.name])
}

deny contains msg if {
    input.kind in ["ClusterRole", "Role"]
    some rule
    rule := input.rules[rule]
    rule.verbs[_] == "*"
    rule.resources[_] == "*"
    msg := sprintf("%s '%s' should not grant wildcard permissions on all resources", [input.kind, input.metadata.name])
}

# Pod Security

deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod"]
    input.spec.template.spec.hostNetwork == true
    msg := sprintf("Pod must not use hostNetwork", [])
}

deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod"]
    input.spec.template.spec.hostPID == true
    msg := sprintf("Pod must not use hostPID", [])
}

deny contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod"]
    input.spec.template.spec.hostIPC == true
    msg := sprintf("Pod must not use hostIPC", [])
}

# Secrets and ConfigMaps

warn contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod"]
    some container
    container := input.spec.template.spec.containers[container]
    some env
    env := container.env[env]
    not env.valueFrom
    contains(lower(env.name), "password")
    msg := sprintf("Container '%s' should use secrets for sensitive environment variables like '%s'", [container.name, env.name])
}

warn contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Pod"]
    some container
    container := input.spec.template.spec.containers[container]
    some env
    env := container.env[env]
    not env.valueFrom
    contains(lower(env.name), "token")
    msg := sprintf("Container '%s' should use secrets for sensitive environment variables like '%s'", [container.name, env.name])
}

# Liveness and Readiness Probes

warn contains msg if {
    input.kind in ["Deployment", "StatefulSet"]
    some container
    container := input.spec.template.spec.containers[container]
    not container.livenessProbe
    msg := sprintf("Container '%s' should define a liveness probe", [container.name])
}

warn contains msg if {
    input.kind in ["Deployment", "StatefulSet"]
    some container
    container := input.spec.template.spec.containers[container]
    not container.readinessProbe
    msg := sprintf("Container '%s' should define a readiness probe", [container.name])
}

# Labels and Annotations

warn contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet", "Service"]
    not input.metadata.labels
    msg := sprintf("%s '%s' should have labels defined", [input.kind, input.metadata.name])
}

warn contains msg if {
    input.kind in ["Deployment", "StatefulSet", "DaemonSet"]
    not input.metadata.labels.app
    msg := sprintf("%s '%s' should have 'app' label defined", [input.kind, input.metadata.name])
}
