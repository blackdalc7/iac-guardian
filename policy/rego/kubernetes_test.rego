package guardian.kubernetes_test

import data.guardian.kubernetes

deployment(pod_spec) := {
	"file": "deploy.yaml",
	"doc": {
		"kind": "Deployment",
		"metadata": {"name": "api"},
		"spec": {"template": {"spec": pod_spec}},
	},
}

ids(obj) := {v.id | some v in kubernetes.violations with input as {"kubernetes": {"objects": [obj]}}}

hardened := {
	"securityContext": {"runAsNonRoot": true},
	"containers": [{
		"name": "api",
		"image": "registry.example/api:1.4.2",
		"securityContext": {"allowPrivilegeEscalation": false},
	}],
}

test_hardened_workload_allowed if {
	count(ids(deployment(hardened))) == 0
}

test_privileged_container_denied if {
	spec := {"containers": [{"name": "api", "securityContext": {"privileged": true}}]}
	ids(deployment(spec)) == {"K8S001", "K8S002", "K8S004"}
}

test_host_network_denied if {
	"K8S003" in ids(deployment(object.union(hardened, {"hostNetwork": true})))
}

test_init_containers_are_checked if {
	spec := object.union(hardened, {"initContainers": [{"name": "setup", "securityContext": {"privileged": true}}]})
	"K8S001" in ids(deployment(spec))
}

test_cronjob_template_is_checked if {
	obj := {
		"file": "cron.yaml",
		"doc": {
			"kind": "CronJob",
			"metadata": {"name": "nightly"},
			"spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": [{"name": "job"}]}}}}},
		},
	}
	ids(obj) == {"K8S002", "K8S004"}
}

# Objects without a pod template (ConfigMap, Service...) are out of scope.
test_non_workload_ignored if {
	count(ids({"file": "cm.yaml", "doc": {"kind": "ConfigMap", "metadata": {"name": "cfg"}}})) == 0
}
