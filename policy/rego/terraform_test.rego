package guardian.terraform_test

import data.guardian.terraform

res(type, name, config) := {
	"kind": "resource",
	"type": type,
	"name": name,
	"address": sprintf("%s.%s", [type, name]),
	"file": "main.tf",
	"config": config,
}

ids(resources) := {v.id | some v in terraform.violations with input as {"terraform": {"resources": resources}}}

locked_bucket := [
	res("aws_s3_bucket", "logs", {"bucket": "logs"}),
	res("aws_s3_bucket_public_access_block", "logs", {
		"bucket": "${aws_s3_bucket.logs.id}",
		"block_public_acls": true,
		"block_public_policy": true,
		"ignore_public_acls": true,
		"restrict_public_buckets": true,
	}),
]

test_public_acl_denied if {
	"TF001" in ids([res("aws_s3_bucket", "logs", {"acl": "public-read"})])
}

test_bucket_without_access_block_denied if {
	ids([res("aws_s3_bucket", "logs", {"bucket": "logs"})]) == {"TF002"}
}

test_locked_bucket_allowed if {
	count(ids(locked_bucket)) == 0
}

# Three of four switches is not enough: the gap is still a bypass.
test_partial_access_block_denied if {
	partial := [
		locked_bucket[0],
		res("aws_s3_bucket_public_access_block", "logs", {
			"bucket": "${aws_s3_bucket.logs.id}",
			"block_public_acls": true,
			"block_public_policy": true,
			"ignore_public_acls": true,
			"restrict_public_buckets": false,
		}),
	]
	"TF002" in ids(partial)
}

# An access block that protects a different bucket must not count.
test_access_block_for_other_bucket_denied if {
	other := [
		res("aws_s3_bucket", "data", {"bucket": "data"}),
		locked_bucket[1],
	]
	"TF002" in ids(other)
}

sg(rules) := res("aws_security_group", "web", {"ingress": rules})

test_ssh_open_to_world_denied if {
	"TF003" in ids([sg([{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}])])
}

test_port_range_covering_rdp_denied if {
	"TF003" in ids([sg([{"from_port": 3000, "to_port": 4000, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}])])
}

test_all_protocols_denied if {
	"TF003" in ids([sg([{"from_port": 0, "to_port": 0, "protocol": "-1", "ipv6_cidr_blocks": ["::/0"]}])])
}

test_ssh_from_private_range_allowed if {
	count(ids([sg([{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"]}])])) == 0
}

test_public_https_allowed if {
	count(ids([sg([{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}])])) == 0
}

policy_doc(stmt) := {
	"kind": "data",
	"type": "aws_iam_policy_document",
	"name": "p",
	"address": "data.aws_iam_policy_document.p",
	"file": "iam.tf",
	"config": {"statement": [stmt]},
}

test_iam_admin_denied if {
	"TF004" in ids([policy_doc({"actions": ["*"], "resources": ["*"]})])
}

test_iam_service_wildcard_denied if {
	"TF004" in ids([policy_doc({"actions": ["s3:*"], "resources": ["*"]})])
}

test_iam_scoped_allowed if {
	count(ids([policy_doc({"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::logs/*"]})])) == 0
}

test_iam_explicit_deny_allowed if {
	count(ids([policy_doc({"effect": "Deny", "actions": ["*"], "resources": ["*"]})])) == 0
}

test_public_unencrypted_db_denied if {
	found := ids([res("aws_db_instance", "db", {"publicly_accessible": true, "engine": "postgres"})])
	found == {"TF005", "TF006"}
}

test_hardened_db_allowed if {
	count(ids([res("aws_db_instance", "db", {"publicly_accessible": false, "storage_encrypted": true})])) == 0
}

# Both resources pass their own checks; only the relationship is unsafe.
test_database_reachable_through_security_group_denied if {
	found := ids([
		res("aws_db_instance", "db", {
			"engine": "postgres",
			"storage_encrypted": true,
			"vpc_security_group_ids": ["${aws_security_group.web.id}"],
		}),
		sg([{"from_port": 5432, "to_port": 5432, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]),
	])
	found == {"TF009"}
}

test_unattached_security_group_not_blamed_for_database if {
	found := ids([
		res("aws_db_instance", "db", {"engine": "postgres", "storage_encrypted": true}),
		sg([{"from_port": 5432, "to_port": 5432, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]),
	])
	count(found) == 0
}

test_imdsv1_denied if {
	"TF007" in ids([res("aws_instance", "app", {"ami": "ami-1"})])
	"TF007" in ids([res("aws_instance", "app", {"metadata_options": [{"http_tokens": "optional"}]})])
}

test_imdsv2_allowed if {
	count(ids([res("aws_instance", "app", {"metadata_options": [{"http_tokens": "required"}]})])) == 0
}

test_unencrypted_volume_denied if {
	"TF008" in ids([res("aws_ebs_volume", "data", {"size": 10})])
}
