"""The knowledge base's conditions, evaluated on real Terraform with the catalogue's own tests."""

import pytest

from terrahunter import conditions, graph, kb


def ev(tmp_path, text, addr, test):
    (tmp_path / "main.tf").write_text(text)
    g = graph.build(tmp_path, ".")
    return conditions.evaluate(test, addr, conditions.Index.of(g))


def exposure(rtype, i):
    return kb.entry(rtype)["exposure"][i]["test"]


def risky(rtype, badge):
    return next(r["test"] for r in kb.entry(rtype)["risky_settings"] if r["badge"] == badge)


POLICY = 'resource "aws_s3_bucket" "b" {{ bucket = "b" }}\nresource "aws_s3_bucket_policy" "p" {{\n  bucket = aws_s3_bucket.b.id\n  policy = <<EOF\n{doc}\nEOF\n}}\n'
PUBLIC = '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]}'
BPA = 'resource "aws_s3_bucket_public_access_block" "x" {\n  bucket = aws_s3_bucket.b.id\n  restrict_public_buckets = true\n}\n'


@pytest.mark.parametrize(
    ("doc", "extra", "want"),
    [
        (PUBLIC, "", True),
        (
            PUBLIC.replace(
                '"Resource": "*"', '"Resource": "*", "Condition": {"Bool": {"aws:SecureTransport": "true"}}'
            ),
            "",
            False,
        ),
        ('{"Statement": {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:*", "Resource": "*"}}', "", True),
        ('{"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*"}]}', "", False),
        (PUBLIC, BPA, False),  # Block Public Access on the bucket
    ],
)
def test_bucket_policy_exposure(tmp_path, doc, extra, want):
    assert ev(tmp_path, POLICY.format(doc=doc) + extra, "aws_s3_bucket.b", exposure("aws_s3_bucket", 0)) is want


def test_policy_from_a_variable_is_unknown(tmp_path):
    text = 'variable "doc" {}\n' + POLICY.format(doc="${var.doc}")
    assert ev(tmp_path, text, "aws_s3_bucket.b", exposure("aws_s3_bucket", 0)) is None


def test_account_scope(tmp_path):
    text = (
        POLICY.format(doc=PUBLIC)
        + 'resource "aws_s3_account_public_access_block" "a" {\n  restrict_public_buckets = true\n}\n'
    )
    assert ev(tmp_path, text, "aws_s3_bucket.b", exposure("aws_s3_bucket", 0)) is False


@pytest.mark.parametrize(
    ("ingress", "want"),
    [
        ('ingress {\n  from_port = 22\n  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n', True),
        ('ingress {\n  from_port = 22\n  to_port = 22\n  protocol = "tcp"\n  cidr_blocks = ["10.0.0.0/8"]\n}\n', False),
        ('ingress {\n  from_port = 443\n  to_port = 443\n  protocol = "tcp"\n  ipv6_cidr_blocks = ["::/0"]\n}\n', True),
    ],
)
def test_security_group(tmp_path, ingress, want):
    text = f'resource "aws_security_group" "s" {{\n{ingress}}}\n'
    assert ev(tmp_path, text, "aws_security_group.s", risky("aws_security_group", "open to internet: <ports>")) is want


SAME_BLOCK = {
    "all": [
        {"attr": "ingress.from_port", "is": 22},
        {"attr": "ingress.cidr_blocks", "contains": "0.0.0.0/0"},
    ]
}


@pytest.mark.parametrize(
    ("blocks", "want"),
    [
        # 22 open only to the VPC, 443 open to the world: no single block passes both checks
        (
            (
                'ingress {\n  from_port = 22\n  cidr_blocks = ["10.0.0.0/8"]\n}\n'
                'ingress {\n  from_port = 443\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
            ),
            False,
        ),
        (
            (
                'ingress {\n  from_port = 443\n  cidr_blocks = ["10.0.0.0/8"]\n}\n'
                'ingress {\n  from_port = 22\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
            ),
            True,
        ),
    ],
)
def test_same_block_instance(tmp_path, blocks, want):
    assert (
        ev(tmp_path, f'resource "aws_security_group" "s" {{\n{blocks}}}\n', "aws_security_group.s", SAME_BLOCK) is want
    )


@pytest.mark.parametrize(
    ("body", "extra", "want"),
    [
        ("", "", True),  # every default leaves it open to all networks
        ("  public_network_access_enabled = false\n", "", False),
        ('  network_rules {\n    default_action = "Deny"\n  }\n', "", False),
        (
            "",
            (
                'resource "azurerm_storage_account_network_rules" "r" {\n'
                '  storage_account_id = azurerm_storage_account.s.id\n  default_action = "Deny"\n}\n'
            ),
            False,
        ),
    ],
)
def test_storage_account_unset_defaults(tmp_path, body, extra, want):
    text = f'resource "azurerm_storage_account" "s" {{\n  name = "s"\n{body}}}\n{extra}'
    assert ev(tmp_path, text, "azurerm_storage_account.s", exposure("azurerm_storage_account", 0)) is want


@pytest.mark.parametrize(
    ("body", "want"),
    [
        ('  source_ranges = ["0.0.0.0/0"]\n  allow {\n    protocol = "tcp"\n    ports = ["22"]\n  }\n', True),
        ('  source_ranges = ["0.0.0.0/0"]\n  direction = "EGRESS"\n  allow {\n    protocol = "tcp"\n  }\n', False),
        ('  source_ranges = ["0.0.0.0/0"]\n  disabled = true\n  allow {\n    protocol = "tcp"\n  }\n', False),
        ('  source_ranges = ["35.235.240.0/20"]\n  allow {\n    protocol = "tcp"\n  }\n', False),
    ],
)
def test_gcp_firewall(tmp_path, body, want):
    text = f'resource "google_compute_firewall" "f" {{\n  network = "default"\n{body}}}\n'
    assert ev(tmp_path, text, "google_compute_firewall.f", exposure("google_compute_firewall", 0)) is want


@pytest.mark.parametrize(("auth", "want"), [("NONE", True), ("AWS_IAM", False)])
def test_function_url_via(tmp_path, auth, want):
    text = (
        'resource "aws_lambda_function" "f" { function_name = "f" }\n'
        f'resource "aws_lambda_function_url" "u" {{\n  function_name = aws_lambda_function.f.function_name\n'
        f'  authorization_type = "{auth}"\n}}\n'
    )
    assert ev(tmp_path, text, "aws_lambda_function.f", exposure("aws_lambda_function", 0)) is want


def test_function_without_url(tmp_path):
    text = 'resource "aws_lambda_function" "f" { function_name = "f" }\n'
    assert ev(tmp_path, text, "aws_lambda_function.f", exposure("aws_lambda_function", 0)) is False


@pytest.mark.parametrize(("policy", "want"), [("", True), ("p", False)])
def test_quantifier_none(tmp_path, policy, want):
    text = 'resource "aws_efs_file_system" "fs" {}\n'
    if policy:
        text += 'resource "aws_efs_file_system_policy" "p" {\n  file_system_id = aws_efs_file_system.fs.id\n  policy = "{}"\n}\n'
    assert ev(tmp_path, text, "aws_efs_file_system.fs", exposure("aws_efs_file_system", 0)) is want


@pytest.mark.parametrize(("public", "want"), [("true", True), ("false", False)])
def test_through_a_launch_template(tmp_path, public, want):
    text = (
        'resource "aws_launch_template" "lt" {\n  network_interfaces {\n'
        f"    associate_public_ip_address = {public}\n  }}\n}}\n"
        'resource "aws_autoscaling_group" "asg" {\n  launch_template {\n    id = aws_launch_template.lt.id\n  }\n}\n'
    )
    test = {
        "attr": "network_interfaces.associate_public_ip_address",
        "in": [True, "true"],
        "of": {"through": "launch_template.id", "type": ["aws_launch_template"]},
    }
    assert ev(tmp_path, text, "aws_autoscaling_group.asg", test) is want


def test_map_key(tmp_path):
    test = {
        "attr": "roles",
        "contains": "unauthenticated",
        "inside": {"format": "map_key"},
        "of": {"type": ["aws_cognito_identity_pool_roles_attachment"], "via": "identity_pool_id"},
    }
    text = (
        'resource "aws_iam_role" "g" {}\nresource "aws_cognito_identity_pool" "p" {}\n'
        'resource "aws_cognito_identity_pool_roles_attachment" "r" {\n'
        "  identity_pool_id = aws_cognito_identity_pool.p.id\n  roles = {\n    unauthenticated = aws_iam_role.g.arn\n  }\n}\n"
    )
    assert ev(tmp_path, text, "aws_cognito_identity_pool.p", test) is True


def test_three_valued_logic():
    assert conditions.all3([True, None]) is None
    assert conditions.all3([None, False]) is False
    assert conditions.any3([None, True]) is True
    assert conditions.not3(None) is None
    assert conditions.quantify("none", []) is True
    assert conditions.quantify("any", []) is False


def test_kb_lookups():
    assert kb.entry("aws_alb") is kb.entry("aws_lb")  # an alias reads as the type it aliases
    assert kb.curated("aws_s3_bucket") and not kb.curated("aws_not_a_type")
    assert ("s3:GetObject", "Read") in kb.aws_actions("S3:get*")
    assert kb.managed_policy("AdministratorAccess")["Statement"][0]["Action"] == "*"
    assert kb.azure_role("Owner")[0]["actions"] == ["*"]
    assert "storage.objects.get" in kb.gcp_role("roles/storage.objectViewer")
    assert kb.version()


DOC = (
    'resource "aws_s3_bucket" "b" {{ bucket = "b" }}\n'
    'data "aws_iam_policy_document" "d" {{\n  statement {{\n    actions = ["s3:GetObject"]\n'
    '    resources = ["*"]\n    principals {{\n      type = "AWS"\n      identifiers = [{who}]\n    }}\n  }}\n}}\n'
    'resource "aws_s3_bucket_policy" "p" {{\n  bucket = aws_s3_bucket.b.id\n'
    "  policy = data.aws_iam_policy_document.d.json\n}}\n"
)


@pytest.mark.parametrize(
    ("who", "want"),
    [
        ('"*"', True),  # a data document reads as the JSON it produces; one principal in a list is that principal
        ("aws_iam_role.r.arn", False),  # a resource's own ARN is never the wildcard
        ('"arn:aws:iam::${data.aws_caller_identity.me.account_id}:root"', False),  # nor is a template with text
        ("var.who", None),  # a variable with no value stays unknown
    ],
)
def test_policy_documents_and_principals(tmp_path, who, want):
    text = 'variable "who" {}\nresource "aws_iam_role" "r" {}\ndata "aws_caller_identity" "me" {}\n' + DOC.format(
        who=who
    )
    assert ev(tmp_path, text, "aws_s3_bucket.b", exposure("aws_s3_bucket", 0)) is want


def test_a_customer_policy_is_never_an_aws_managed_one(tmp_path):
    text = (
        'resource "aws_iam_role" "r" {}\nresource "aws_iam_policy" "mine" {}\n'
        'resource "aws_iam_role_policy_attachment" "a" {\n  role = aws_iam_role.r.name\n'
        "  policy_arn = aws_iam_policy.mine.arn\n}\n"
    )
    test = risky("aws_iam_role_policy_attachment", "administrator")
    assert ev(tmp_path, text, "aws_iam_role_policy_attachment.a", test) is False
