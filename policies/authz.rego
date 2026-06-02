package authz

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Default deny
# ---------------------------------------------------------------------------
default allow = false
default audit_required = false

# ---------------------------------------------------------------------------
# Allowlists
# ---------------------------------------------------------------------------

privileged_services := {
    "spiffe://cluster.local/ns/soc-platform/sa/alert-processor",
    "spiffe://cluster.local/ns/soc-platform/sa/correlation-engine",
    "spiffe://cluster.local/ns/security/sa/incident-responder",
    "spiffe://cluster.local/ns/admin/sa/policy-manager",
}

admin_paths := {
    "/admin",
    "/admin/users",
    "/admin/config",
    "/api/v1/admin",
}

read_only_methods := {"GET", "HEAD", "OPTIONS"}
write_methods := {"POST", "PUT", "PATCH"}

# ---------------------------------------------------------------------------
# SPIFFE ID validation helpers
# ---------------------------------------------------------------------------

valid_spiffe_pattern := `^spiffe://[a-z0-9\-\.]+/ns/[a-z0-9\-]+/sa/[a-z0-9\-]+$`

valid_service if {
    input.source_spiffe_id != null
    input.source_spiffe_id != ""
    regex.match(valid_spiffe_pattern, input.source_spiffe_id)
    trust_domain_ok
}

trust_domain_ok if {
    startswith(input.source_spiffe_id, "spiffe://cluster.local/")
}

privileged_service if {
    input.source_spiffe_id in privileged_services
}

# ---------------------------------------------------------------------------
# Allow rules
# ---------------------------------------------------------------------------

# Allow read-only methods for any valid service
allow if {
    input.method in read_only_methods
    valid_service
    not path_requires_privilege(input.path)
}

# Allow write methods only for privileged services
allow if {
    input.method in write_methods
    privileged_service
    valid_service
    valid_path(input.path)
}

# Allow DELETE for privileged services on non-admin paths
allow if {
    input.method == "DELETE"
    privileged_service
    valid_service
    not is_admin_path(input.path)
}

# ---------------------------------------------------------------------------
# Path validation helpers
# ---------------------------------------------------------------------------

valid_path(path) if {
    not is_admin_path(path)
}

valid_path(path) if {
    is_admin_path(path)
    privileged_service
}

is_admin_path(path) if {
    some admin_prefix in admin_paths
    startswith(path, admin_prefix)
}

path_requires_privilege(path) if {
    is_admin_path(path)
}

# ---------------------------------------------------------------------------
# Audit requirements
# ---------------------------------------------------------------------------

# Audit required for DELETE operations
audit_required if {
    input.method == "DELETE"
}

# Audit required for admin path access
audit_required if {
    is_admin_path(input.path)
}

# Audit required for privileged write operations
audit_required if {
    input.method in write_methods
    privileged_service
}

# ---------------------------------------------------------------------------
# Deny reasons (for structured logging)
# ---------------------------------------------------------------------------

deny_reason := reason if {
    not valid_service
    reason := "invalid_spiffe_id"
}

deny_reason := reason if {
    valid_service
    not trust_domain_ok
    reason := "untrusted_trust_domain"
}

deny_reason := reason if {
    valid_service
    input.method in write_methods
    not privileged_service
    reason := "insufficient_privilege_for_write"
}

deny_reason := reason if {
    valid_service
    is_admin_path(input.path)
    not privileged_service
    reason := "admin_path_requires_privileged_service"
}

# _r 20260602101905-74f45680
