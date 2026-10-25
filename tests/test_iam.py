"""The IAM model: what each identity may do, and who may become a role."""

import pytest

from terrahunter import graph, iam


def model(tmp_path, text):
    (tmp_path / "main.tf").write_text(text)
    return iam.Model(graph.build(tmp_path, "."))


def policy(name, statements, role="aws_iam_role.r"):
    return (
        f'resource "aws_iam_role_policy" "{name}" {{\n  role = {role}.id\n'
        f"  policy = jsonencode({{Statement = [{statements}]}})\n}}\n"
    )


BUCKET = 'resource "aws_s3_bucket" "data" {\n  bucket = "acme-data"\n}\nresource "aws_s3_bucket" "logs" {}\n'
ROLE = 'resource "aws_iam_role" "r" {}\n'


def test_allow_on_a_referenced_resource(tmp_path):
    m = model(
        tmp_path,
        ROLE + BUCKET + policy("p", '{Effect = "Allow", Action = "s3:Get*", Resource = "${aws_s3_bucket.data.arn}/*"}'),
    )
    assert m.allowed("aws_iam_role.r", "s3:GetObject", "aws_s3_bucket.data") is True
    assert m.allowed("aws_iam_role.r", "s3:GetObject", "aws_s3_bucket.logs") is False
    assert m.allowed("aws_iam_role.r", "s3:PutObject", "aws_s3_bucket.data") is False
    assert m.access("aws_iam_role.r", "aws_s3_bucket.data", "s3") == "read"


def test_a_literal_arn_names_a_bucket_by_its_name(tmp_path):
    m = model(
        tmp_path,
        ROLE + BUCKET + policy("p", '{Effect = "Allow", Action = "s3:*", Resource = "arn:aws:s3:::acme-*"}'),
    )
    assert m.allowed("aws_iam_role.r", "s3:DeleteObject", "aws_s3_bucket.data") is True
    assert m.access("aws_iam_role.r", "aws_s3_bucket.data", "s3") == "admin"


def test_deny_beats_allow_and_conditions_are_unsure(tmp_path):
    m = model(
        tmp_path,
        ROLE
        + BUCKET
        + policy("a", '{Effect = "Allow", Action = "*", Resource = "*"}')
        + policy("d", '{Effect = "Deny", Action = "s3:DeleteObject", Resource = "*"}')
        + policy(
            "c",
            '{Effect = "Allow", Action = "kms:Decrypt", Resource = "*", '
            'Condition = {Bool = {"aws:MultiFactorAuthPresent" = "true"}}}',
            role="aws_iam_role.r",
        ),
    )
    assert m.allowed("aws_iam_role.r", "s3:DeleteObject", "aws_s3_bucket.data") is False
    assert m.allowed("aws_iam_role.r", "s3:GetObject", "aws_s3_bucket.data") is True


def test_not_action(tmp_path):
    m = model(tmp_path, ROLE + policy("p", '{Effect = "Allow", NotAction = "iam:*", Resource = "*"}'))
    assert m.allowed("aws_iam_role.r", "s3:GetObject") is True
    assert m.allowed("aws_iam_role.r", "iam:CreateUser") is False


def test_managed_policies_groups_and_inline_blocks(tmp_path):
    m = model(
        tmp_path,
        'resource "aws_iam_user" "u" {}\nresource "aws_iam_group" "g" {}\n'
        'resource "aws_iam_user_group_membership" "m" {\n  user = aws_iam_user.u.name\n'
        "  groups = [aws_iam_group.g.name]\n}\n"
        'resource "aws_iam_group_policy_attachment" "a" {\n  group = aws_iam_group.g.name\n'
        '  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"\n}\n'
        'resource "aws_iam_role" "r" {\n  inline_policy {\n    name = "i"\n'
        '    policy = jsonencode({Statement = [{Effect = "Allow", Action = "sqs:SendMessage", Resource = "*"}]})\n'
        "  }\n}\n",
    )
    assert m.allowed("aws_iam_user.u", "s3:GetObject") is True
    assert m.allowed("aws_iam_user.u", "s3:PutObject") is False
    assert m.allowed("aws_iam_role.r", "sqs:SendMessage") is True


def test_a_data_policy_document(tmp_path):
    m = model(
        tmp_path,
        ROLE + 'data "aws_iam_policy_document" "d" {\n  statement {\n    actions = ["dynamodb:Query"]\n'
        '    resources = ["*"]\n  }\n}\n'
        'resource "aws_iam_policy" "p" {\n  policy = data.aws_iam_policy_document.d.json\n}\n'
        'resource "aws_iam_role_policy_attachment" "a" {\n  role = aws_iam_role.r.name\n'
        "  policy_arn = aws_iam_policy.p.arn\n}\n",
    )
    assert m.allowed("aws_iam_role.r", "dynamodb:Query") is True


TRUST = (
    'resource "aws_iam_user" "u" {{}}\nresource "aws_iam_user" "other" {{}}\n'
    'resource "aws_iam_role" "t" {{\n  assume_role_policy = jsonencode({{Statement = [{{Effect = "Allow", '
    'Action = "sts:AssumeRole", Principal = {{{principal}}}}}]}})\n}}\n'
)


@pytest.mark.parametrize(
    ("principal", "grant", "want"),
    [
        ("AWS = aws_iam_user.u.arn", "", True),  # named: the same account needs nothing more
        ('AWS = "arn:aws:iam::123456789012:root"', "", False),  # the account root: needs its own permission
        (
            'AWS = "arn:aws:iam::123456789012:root"',
            policy("p", '{Effect = "Allow", Action = "sts:AssumeRole", Resource = "*"}', role="aws_iam_user.u")
            .replace("aws_iam_role_policy", "aws_iam_user_policy")
            .replace("  role = ", "  user = "),
            True,
        ),
        ('Service = "lambda.amazonaws.com"', "", False),
    ],
)
def test_trust(tmp_path, principal, grant, want):
    m = model(tmp_path, TRUST.format(principal=principal) + grant)
    assert m.can_assume("aws_iam_user.u", "aws_iam_role.t") is want
    assert m.can_assume("aws_iam_user.other", "aws_iam_role.t") is False  # neither named nor granted


def test_services_a_role_trusts(tmp_path):
    m = model(tmp_path, TRUST.format(principal='Service = ["lambda.amazonaws.com", "ec2.amazonaws.com"]'))
    assert m.services("aws_iam_role.t") == {"lambda.amazonaws.com", "ec2.amazonaws.com"}


def test_an_arn_with_an_interpolation_names_by_its_literal_tail(tmp_path):
    m = model(
        tmp_path,
        'resource "aws_iam_role" "r" {}\nresource "aws_iam_role" "agentcore_runtime" {\n  name = "agentcore_runtime"\n}\n'
        'resource "aws_iam_role" "other" {\n  name = "other"\n}\ndata "aws_caller_identity" "me" {}\n'
        + policy(
            "p",
            '{Effect = "Allow", Action = "iam:PassRole", '
            'Resource = "arn:aws:iam::${data.aws_caller_identity.me.account_id}:role/agentcore_*"}',
        ),
    )
    assert m.allowed("aws_iam_role.r", "iam:PassRole", "aws_iam_role.agentcore_runtime") is True
    assert m.allowed("aws_iam_role.r", "iam:PassRole", "aws_iam_role.other") is False
