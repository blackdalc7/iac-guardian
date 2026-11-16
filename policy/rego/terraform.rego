# Terraform (AWS) guardrails.
#
# Input shape (built by src/iac/normalize.js):
#   input.terraform.resources[_] = {kind, type, name, address, file, config}
#
# Nested HCL blocks arrive as arrays, so every block lookup iterates.
package guardian.terraform

world_cidrs := {"0.0.0.0/0", "::/0"}

admin_ports := {22, 3389}

# Default listener port per RDS engine, used when `port` is not set explicitly.
engine_ports := {
	"postgres": 5432,
	"aurora-postgresql": 5432,
	"mysql": 3306,
	"mariadb": 3306,
	"aurora-mysql": 3306,
	"sqlserver-ex": 1433,
	"sqlserver-se": 1433,
	"oracle-se2": 1521,
}

resources contains r if {
	some r in input.terraform.resources
	r.kind == "resource"
}

data_sources contains r if {
	some r in input.terraform.resources
	r.kind == "data"
}

violation(id, severity, r, title, msg) := {
	"id": id,
	"severity": severity,
	"resource": r.address,
	"file": r.file,
	"title": title,
	"msg": msg,
}

# ---------------------------------------------------------------- S3

public_acls := {"public-read", "public-read-write", "authenticated-read"}

# TF001 - a canned ACL that grants access to everyone.
violations contains v if {
	some r in resources
	r.type in {"aws_s3_bucket", "aws_s3_bucket_acl"}
	r.config.acl in public_acls
	v := violation(
		"TF001", "critical", r, "S3 bucket is world-readable",
		sprintf("%s uses the '%s' canned ACL, exposing objects to anyone on the internet", [r.address, r.config.acl]),
	)
}

# A bucket is "locked" when some public access block points at it and
# enables all four switches. Anything less leaves a policy/ACL bypass open.
bucket_locked(bucket) if {
	some pab in resources
	pab.type == "aws_s3_bucket_public_access_block"
	references(pab.config.bucket, bucket)
	pab.config.block_public_acls == true
	pab.config.block_public_policy == true
	pab.config.ignore_public_acls == true
	pab.config.restrict_public_buckets == true
}

# TF002 - cross-resource check: the bucket itself can look fine while the
# missing companion resource is what makes it exposable later.
violations contains v if {
	some r in resources
	r.type == "aws_s3_bucket"
	not bucket_locked(r)
	v := violation(
		"TF002", "high", r, "S3 bucket has no complete public access block",
		sprintf("%s is not covered by an aws_s3_bucket_public_access_block with all four protections enabled", [r.address]),
	)
}

# -------------------------------------------------- security groups

ingress_rules(sg) := [rule | some rule in object.get(sg.config, "ingress", [])]

open_to_world(rule) if {
	some cidr in object.get(rule, "cidr_blocks", [])
	cidr in world_cidrs
}

open_to_world(rule) if {
	some cidr in object.get(rule, "ipv6_cidr_blocks", [])
	cidr in world_cidrs
}

covers_port(rule, port) if {
	rule.from_port <= port
	rule.to_port >= port
}

# protocol "-1" means every protocol and port regardless of the range given.
covers_port(rule, _) if rule.protocol == "-1"

# TF003 - management ports reachable from the whole internet.
violations contains v if {
	some r in resources
	r.type == "aws_security_group"
	some rule in ingress_rules(r)
	open_to_world(rule)
	some port in admin_ports
	covers_port(rule, port)
	v := violation(
		"TF003", "critical", r, "Admin port open to the internet",
		sprintf("%s allows ingress from any address to port %d", [r.address, port]),
	)
}

# ---------------------------------------------------------------- IAM

wildcard_action(action) if contains(action, "*")

# TF004 - Allow + wildcard action + wildcard resource is admin in disguise.
violations contains v if {
	some r in data_sources
	r.type == "aws_iam_policy_document"
	some stmt in object.get(r.config, "statement", [])
	object.get(stmt, "effect", "Allow") == "Allow"
	"*" in object.get(stmt, "resources", [])
	some action in object.get(stmt, "actions", [])
	wildcard_action(action)
	v := violation(
		"TF004", "high", r, "IAM statement is over-permissive",
		sprintf("%s allows '%s' on every resource", [r.address, action]),
	)
}

# ---------------------------------------------------------------- RDS

# TF005
violations contains v if {
	some r in resources
	r.type == "aws_db_instance"
	r.config.publicly_accessible == true
	v := violation(
		"TF005", "critical", r, "Database has a public endpoint",
		sprintf("%s sets publicly_accessible = true", [r.address]),
	)
}

# TF006
violations contains v if {
	some r in resources
	r.type == "aws_db_instance"
	object.get(r.config, "storage_encrypted", false) != true
	v := violation(
		"TF006", "high", r, "Database storage is not encrypted",
		sprintf("%s does not enable storage_encrypted", [r.address]),
	)
}

db_port(db) := db.config.port if db.config.port

db_port(db) := engine_ports[db.config.engine] if not db.config.port

# TF009 - the "logical" one. Neither resource is wrong in isolation: the
# flaw is the path internet -> security group -> database listener.
violations contains v if {
	some db in resources
	db.type == "aws_db_instance"
	some sg in resources
	sg.type == "aws_security_group"
	some ref in object.get(db.config, "vpc_security_group_ids", [])
	references(ref, sg)
	some rule in ingress_rules(sg)
	open_to_world(rule)
	port := db_port(db)
	covers_port(rule, port)
	base := violation(
		"TF009", "critical", db, "Internet-reachable path to database",
		sprintf("%s is attached to %s, which accepts traffic from any address on port %d", [db.address, sg.address, port]),
	)

	# `related` tells the scope guard which other resource a fix may touch.
	v := object.union(base, {"related": [sg.address]})
}

# ---------------------------------------------------------------- EC2

imds_v2_enforced(r) if {
	some opts in object.get(r.config, "metadata_options", [])
	opts.http_tokens == "required"
}

# TF007 - IMDSv1 turns any SSRF into credential theft (Capital One, 2019).
violations contains v if {
	some r in resources
	r.type == "aws_instance"
	not imds_v2_enforced(r)
	v := violation(
		"TF007", "high", r, "Instance metadata service v1 is enabled",
		sprintf("%s does not require IMDSv2 session tokens", [r.address]),
	)
}

# TF008
violations contains v if {
	some r in resources
	r.type == "aws_ebs_volume"
	object.get(r.config, "encrypted", false) != true
	v := violation(
		"TF008", "medium", r, "EBS volume is not encrypted",
		sprintf("%s does not set encrypted = true", [r.address]),
	)
}

# ------------------------------------------------------------ helpers

# True when an expression string interpolates the given resource,
# e.g. "${aws_s3_bucket.logs.id}" references aws_s3_bucket.logs.
references(expr, r) if {
	is_string(expr)
	contains(expr, sprintf("%s.", [r.address]))
}
