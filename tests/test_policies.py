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
