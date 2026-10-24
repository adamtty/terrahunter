"""Cognito: a user pool anyone can sign up to, or an identity pool that admits guests, hands out a role."""

import pytest

from terrahunter import arch, chains, graph

ROLE = (
    'resource "aws_dynamodb_table" "orders" {}\nresource "aws_iam_role" "authenticated" {}\nresource "aws_iam_role" "guest" {}\n'
    'resource "aws_iam_role_policy" "p" {\n  role = aws_iam_role.authenticated.id\n  policy = <<EOF\n'
    '{"Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "*"}]}\nEOF\n}\n'
    'resource "aws_iam_role_policy" "g" {\n  role = aws_iam_role.guest.id\n  policy = <<EOF\n'
    '{"Statement": [{"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "*"}]}\nEOF\n}\n'
)


def pools(admin_only: str = "", client: bool = True, guests: bool = False) -> str:
    cfg = (
        f"  admin_create_user_config {{\n    allow_admin_create_user_only = {admin_only}\n  }}\n" if admin_only else ""
    )
    out = f'resource "aws_cognito_user_pool" "users" {{\n{cfg}}}\n'
    if client:
        out += (
            'resource "aws_cognito_user_pool_client" "web" {\n  user_pool_id = aws_cognito_user_pool.users.id\n'
            "  generate_secret = false\n}\n"
        )
    out += (
        f'resource "aws_cognito_identity_pool" "ids" {{\n  allow_unauthenticated_identities = {str(guests).lower()}\n'
        "  cognito_identity_providers {\n"
        + ("    client_id = aws_cognito_user_pool_client.web.id\n" if client else "")
        + '    provider_name = "cognito-idp.eu-west-1.amazonaws.com/${aws_cognito_user_pool.users.id}"\n  }\n}\n'
        'resource "aws_cognito_identity_pool_roles_attachment" "r" {\n  identity_pool_id = aws_cognito_identity_pool.ids.id\n'
        "  roles = {\n    authenticated = aws_iam_role.authenticated.arn\n    unauthenticated = aws_iam_role.guest.arn\n  }\n}\n"
    )
    return out


def build(tmp_path, text):
    (tmp_path / "main.tf").write_text(text)
    g = graph.build(tmp_path, ".")
    return chains.build(g, arch.build(g))


def test_anyone_can_sign_up(tmp_path):
    r = build(tmp_path, ROLE + pools())
    by_role = {c.steps[-1]: c for c in r.chains}
    c = by_role["aws_iam_role.authenticated"]
    assert c.steps == [
        "internet",
        "aws_cognito_user_pool.users",
        "aws_cognito_identity_pool.ids",
        "aws_iam_role.authenticated",
    ]
    assert (c.sinks, c.confidence, c.severity) == (["aws_dynamodb_table.orders"], "direct", "critical")
    fix = next(f for f in r.fixes if f.id == "public:aws_cognito_user_pool.users")
    assert "allow_admin_create_user_only" in fix.action
    assert set(by_role) == {"aws_iam_role.authenticated"}  # signing in gives the authenticated role only


@pytest.mark.parametrize("text", [pools(admin_only="true"), pools(client=False)])
def test_no_sign_up(tmp_path, text):
    assert build(tmp_path, ROLE + text).chains == []


def test_guests(tmp_path):
    r = build(tmp_path, ROLE + pools(admin_only="true", guests=True))
    steps = {tuple(c.steps) for c in r.chains}
    assert ("internet", "aws_cognito_identity_pool.ids", "aws_iam_role.guest") in steps
    assert any("allow_unauthenticated_identities" in f.action for f in r.fixes)
