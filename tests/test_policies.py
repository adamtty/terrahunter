"""Resource policies that let anyone in: read in every form Terraform writes them, judged the way S3 judges a policy
public, and turned into attack paths (with the policy as the place to fix it)."""

import pytest

from terrahunter import arch, chains, graph, policies

ROLE = (
    'resource "aws_iam_role" "fn" {}\n'
    'resource "aws_iam_role_policy" "p" {\n  role = aws_iam_role.fn.id\n  policy = <<EOF\n'
    '{"Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}]}\nEOF\n}\n'
    'resource "aws_dynamodb_table" "orders" {}\n'
    'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n  role = aws_iam_role.fn.arn\n}\n'
)


def build(tmp_path, text: str):
    (tmp_path / "main.tf").write_text(text)
    g = graph.build(tmp_path, ".")
    return chains.build(g, arch.build(g))


@pytest.mark.parametrize(
    ("value", "public"),
    [
        (
            (
                '"<<EOF\n{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", '
                '"Resource": "${aws_s3_bucket.b.arn}/*"}]}\nEOF"'
            ),
            True,
        ),
        ('${jsonencode({Statement = [{Effect = "Allow", Principal = {AWS = "*"}, Action = "sns:Publish"}]})}', True),
        (
            (
                '${jsonencode({Statement = [{Effect = "Allow", Principal = "*", Action = "s3:GetObject", '
                'Condition = {StringLike = {"aws:Referer" = ["https://x"]}}}]})}'
            ),
            True,
        ),  # a header anyone can forge
        (
            (
                '${jsonencode({Statement = [{Effect = "Allow", Principal = "*", Action = "s3:GetObject", '
                'Condition = {IpAddress = {"aws:SourceIp" = ["203.0.113.0/24"]}}}]})}'
            ),
            False,
        ),
        (
            (
                '${jsonencode({Statement = [{Effect = "Allow", Principal = "*", Action = "s3:GetObject", '
                'Condition = {IpAddress = {"aws:SourceIp" = ["0.0.0.0/0"]}}}]})}'
            ),
            True,
        ),
        ('${jsonencode({Statement = [{Effect = "Deny", Principal = "*", Action = "s3:*"}]})}', False),
        ('${jsonencode({Statement = [{Effect = "Allow", Principal = {Service = "lambda.amazonaws.com"}}]})}', False),
        ("${data.aws_iam_policy_document.d.json}", None),  # a reference: not a literal
    ],
)
def test_reading_and_judging_policies(value, public):
    doc = policies.document(value)
    if public is None:
        assert doc is None
    else:
        assert any(policies.is_public(s) for s in policies.statements(doc)) is public


def test_a_public_bucket_policy_unless_block_public_access(tmp_path):
    bucket = (
        'resource "aws_s3_bucket" "site" {}\n'
        'data "aws_iam_policy_document" "d" {\n  statement {\n    principals {\n      type = "*"\n'
        '      identifiers = ["*"]\n    }\n    actions = ["s3:GetObject"]\n    resources = ["*"]\n  }\n}\n'
        'resource "aws_s3_bucket_policy" "p" {\n  bucket = aws_s3_bucket.site.id\n'
        "  policy = data.aws_iam_policy_document.d.json\n}\n"
    )
    r = build(tmp_path, bucket)
    (c,) = r.chains
    assert (c.steps, c.sinks, c.confidence) == (["internet"], ["aws_s3_bucket.site"], "direct")
    assert "bucket policy lets anyone s3:GetObject" in c.entry
    assert r.fixes[0].where[0]["address"] == "aws_s3_bucket_policy.p"
    bpa = 'resource "aws_s3_bucket_public_access_block" "b" {\n  bucket = aws_s3_bucket.site.id\n  restrict_public_buckets = true\n}\n'
    assert build(tmp_path, bucket + bpa).chains == []
    acct = 'resource "aws_s3_account_public_access_block" "a" {\n  restrict_public_buckets = true\n}\n'
    assert build(tmp_path, bucket + acct).chains == []


def test_topics_and_queues_any_account_can_use(tmp_path):
    r = build(
        tmp_path,
        'resource "aws_sqs_queue" "orders" {}\nresource "aws_sqs_queue_policy" "p" {\n'
        "  queue_url = aws_sqs_queue.orders.id\n  policy = <<POLICY\n"
        '{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sqs:SendMessage", '
        '"Resource": "${aws_sqs_queue.orders.arn}"}]}\nPOLICY\n}\n'
        'resource "aws_sns_topic" "news" {\n  policy = jsonencode({Statement = [{Effect = "Allow", '
        'Principal = "*", Action = ["sns:Subscribe", "sns:Publish"]}]})\n}\n',
    )
    assert sorted(c.sinks[0] for c in r.chains) == ["aws_sns_topic.news", "aws_sqs_queue.orders"]
    assert all(c.confidence == "direct" for c in r.chains)


def test_a_lambda_permission_for_anyone(tmp_path):
    r = build(
        tmp_path,
        ROLE + 'resource "aws_lambda_permission" "any" {\n  function_name = aws_lambda_function.fn.function_name\n'
        '  principal = "*"\n  action = "lambda:InvokeFunction"\n}\n',
    )
    (c,) = r.chains
    assert c.steps == ["internet", "aws_lambda_function.fn", "aws_iam_role.fn"]
    assert c.sinks == ["aws_dynamodb_table.orders"]
    with_source = ROLE + (
        'resource "aws_lambda_permission" "s3" {\n  function_name = aws_lambda_function.fn.function_name\n'
        '  principal = "*"\n  source_arn = "arn:aws:s3:::x"\n}\n'
    )
    assert build(tmp_path, with_source).chains == []


def test_api_gateway_with_no_authorizer(tmp_path):
    api = ROLE + (
        'resource "aws_api_gateway_rest_api" "api" {}\n'
        'resource "aws_api_gateway_method" "get" {\n  rest_api_id = aws_api_gateway_rest_api.api.id\n'
        '  http_method = "GET"\n  authorization = "NONE"\n}\n'
        'resource "aws_api_gateway_integration" "i" {\n  rest_api_id = aws_api_gateway_rest_api.api.id\n'
        "  uri = aws_lambda_function.fn.invoke_arn\n}\n"
    )
    r = build(tmp_path, api)
    (c,) = r.chains
    assert c.steps == ["internet", "aws_api_gateway_rest_api.api", "aws_lambda_function.fn", "aws_iam_role.fn"]
    assert "GET method with no authorizer" in c.entry and c.sinks == ["aws_dynamodb_table.orders"]
    assert "authorizer" in r.fixes[0].action and r.fixes[0].where[0]["address"] == "aws_api_gateway_method.get"
    private = api.replace(
        'resource "aws_api_gateway_rest_api" "api" {}',
        'resource "aws_api_gateway_rest_api" "api" {\n  endpoint_configuration {\n    types = ["PRIVATE"]\n  }\n}',
    )
    assert build(tmp_path, private).chains == []
    v2 = ROLE + (
        'resource "aws_apigatewayv2_api" "http" {}\n'
        'resource "aws_apigatewayv2_route" "r" {\n  api_id = aws_apigatewayv2_api.http.id\n  route_key = "GET /x"\n}\n'
        'resource "aws_apigatewayv2_integration" "i" {\n  api_id = aws_apigatewayv2_api.http.id\n'
        "  integration_uri = aws_lambda_function.fn.invoke_arn\n}\n"
    )
    (c,) = build(tmp_path, v2).chains  # a route's authorization_type defaults to NONE
    assert c.steps[1:3] == ["aws_apigatewayv2_api.http", "aws_lambda_function.fn"]


@pytest.mark.parametrize(("op", "public"), [("IpAddress", True), ("NotIpAddress", False)])
def test_a_source_ip_list_that_includes_everyone(tmp_path, op, public):
    r = build(
        tmp_path,
        'variable "w" {\n  default = ["0.0.0.0/0"]\n}\nresource "aws_eip" "ip" {}\nresource "aws_s3_bucket" "b" {}\n'
        'resource "aws_s3_bucket_policy" "p" {\n  bucket = aws_s3_bucket.b.id\n  policy = jsonencode({\n'
        '    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject",\n'
        f'      Condition = {{ {op} = {{ "aws:SourceIp" = concat(var.w, ["${{aws_eip.ip.public_ip}}/32"]) }} }} }}]\n'
        "  })\n}\n",
    )
    assert bool(r.chains) is public


def test_an_api_that_calls_aws_as_its_role(tmp_path):
    r = build(
        tmp_path,
        'resource "aws_s3_bucket" "site" {}\nresource "aws_iam_role" "apigw" {}\n'
        'resource "aws_iam_role_policy" "p" {\n  role = aws_iam_role.apigw.id\n  policy = <<EOF\n'
        '{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "${aws_s3_bucket.site.arn}/*"}]}\nEOF\n}\n'
        'resource "aws_api_gateway_rest_api" "api" {}\n'
        'resource "aws_api_gateway_method" "get" {\n  rest_api_id = aws_api_gateway_rest_api.api.id\n'
        '  http_method = "GET"\n  authorization = "NONE"\n}\n'
        'resource "aws_api_gateway_integration" "s3" {\n  rest_api_id = aws_api_gateway_rest_api.api.id\n'
        '  type = "AWS"\n  credentials = aws_iam_role.apigw.arn\n}\n',
    )
    (c,) = r.chains
    assert c.steps == ["internet", "aws_api_gateway_rest_api.api", "aws_iam_role.apigw"]
    assert (c.sinks, c.confidence) == (["aws_s3_bucket.site"], "direct")


def test_a_condition_on_an_unknown_value_is_possibly_public(tmp_path):
    # the policy admits only an address from a variable terrahunter has no value for: not dropped, possible
    topic = (
        'variable "ip" {}\nresource "aws_sns_topic" "t" {}\n'
        'resource "aws_sns_topic_policy" "p" {\n  arn = aws_sns_topic.t.arn\n  policy = jsonencode({\n'
        '    Statement = [{Effect = "Allow", Principal = "*", Action = ["sns:Subscribe"], Resource = "*",\n'
        '      Condition = {IpAddress = {"aws:SourceIp" = "${var.ip}/32"}}}]\n  })\n}\n'
    )
    (c,) = build(tmp_path, topic).chains
    assert (c.sinks, c.confidence) == (["aws_sns_topic.t"], "possible")
    assert "may let any AWS account sns:Subscribe" in c.entry


@pytest.mark.parametrize(("keyed", "confidence"), [("false", "direct"), ("true", "possible")])
def test_a_public_api_with_nothing_behind_it_is_still_a_path(tmp_path, keyed, confidence):
    text = (
        'resource "aws_api_gateway_rest_api" "api" {}\n'
        'resource "aws_api_gateway_method" "m" {\n  rest_api_id = aws_api_gateway_rest_api.api.id\n'
        f'  http_method = "GET"\n  authorization = "NONE"\n  api_key_required = {keyed}\n}}\n'
        'resource "aws_api_gateway_integration" "i" {\n  rest_api_id = aws_api_gateway_rest_api.api.id\n'
        '  http_method = aws_api_gateway_method.m.http_method\n  type = "MOCK"\n}\n'
    )
    (c,) = build(tmp_path, text).chains
    assert (c.kind, c.steps, c.confidence) == ("exposed API", ["internet", "aws_api_gateway_rest_api.api"], confidence)


@pytest.mark.parametrize(("key", "internet"), [("", False), ("  kms_key_id = aws_kms_key.k.arn\n", True)])
def test_a_public_secret_on_the_aws_managed_key_is_only_open_to_the_account(tmp_path, key, internet):
    text = (
        'resource "aws_kms_key" "k" {}\n'
        f'resource "aws_secretsmanager_secret" "s" {{\n{key}}}\n'
        'resource "aws_secretsmanager_secret_policy" "p" {\n  secret_arn = aws_secretsmanager_secret.s.arn\n'
        '  policy = jsonencode({Statement = [{Effect = "Allow", Principal = "*", '
        'Action = "secretsmanager:GetSecretValue", Resource = "*"}]})\n}\n'
    )
    (tmp_path / "main.tf").write_text(text)
    g = graph.build(tmp_path, ".")
    m = arch.build(g)
    assert ("aws_secretsmanager_secret.s" in m.exposed) is internet
    assert ("aws_secretsmanager_secret.s" in m.account_open) is not internet
