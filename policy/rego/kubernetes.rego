# Kubernetes workload hardening, aligned with the "restricted" Pod Security
# Standard.
#
# Input shape: input.kubernetes.objects[_] = {file, doc}
package guardian.kubernetes

# Where the pod template lives differs per workload kind.
pod_spec(doc) := doc.spec if doc.kind == "Pod"

pod_spec(doc) := doc.spec.template.spec if doc.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

pod_spec(doc) := doc.spec.jobTemplate.spec.template.spec if doc.kind == "CronJob"

containers(spec) := array.concat(
	object.get(spec, "containers", []),
	object.get(spec, "initContainers", []),
)

address(doc) := sprintf("%s/%s", [doc.kind, object.get(doc.metadata, "name", "unnamed")])

violation(id, severity, obj, title, msg) := {
	"id": id,
	"severity": severity,
	"resource": address(obj.doc),
	"file": obj.file,
	"title": title,
	"msg": msg,
}

# K8S001 - privileged containers share the node's kernel capabilities.
violations contains v if {
	some obj in input.kubernetes.objects
	some c in containers(pod_spec(obj.doc))
	c.securityContext.privileged == true
	v := violation(
		"K8S001", "critical", obj, "Privileged container",
		sprintf("container '%s' in %s runs privileged", [c.name, address(obj.doc)]),
	)
}

non_root(spec, _) if spec.securityContext.runAsNonRoot == true

non_root(_, c) if c.securityContext.runAsNonRoot == true

# K8S002 - either the pod or the container must refuse to run as UID 0.
violations contains v if {
	some obj in input.kubernetes.objects
	spec := pod_spec(obj.doc)
	some c in containers(spec)
	not non_root(spec, c)
	v := violation(
		"K8S002", "high", obj, "Container may run as root",
		sprintf("container '%s' in %s does not set runAsNonRoot", [c.name, address(obj.doc)]),
	)
}

# K8S003 - host namespaces break the isolation boundary entirely.
violations contains v if {
	some obj in input.kubernetes.objects
	spec := pod_spec(obj.doc)
	some field in ["hostNetwork", "hostPID", "hostIPC"]
	spec[field] == true
	v := violation(
		"K8S003", "high", obj, "Pod shares a host namespace",
		sprintf("%s sets %s: true", [address(obj.doc), field]),
	)
}

# K8S004 - must be explicitly false; the default permits setuid escalation.
violations contains v if {
	some obj in input.kubernetes.objects
	some c in containers(pod_spec(obj.doc))
	object.get(object.get(c, "securityContext", {}), "allowPrivilegeEscalation", true) != false
	v := violation(
		"K8S004", "medium", obj, "Privilege escalation not disabled",
		sprintf("container '%s' in %s does not set allowPrivilegeEscalation: false", [c.name, address(obj.doc)]),
	)
}
