"""If these credentials leak: what an attacker holding one identity can become and reach."""

from terrahunter import arch, escalate, graph


def search(tmp_path, text, start):
    (tmp_path / "main.tf").write_text(text)
    g = graph.build(tmp_path, ".")
    return escalate.search(g, arch.build(g), start)


def user_policy(user, statements):
    return (
        f'resource "aws_iam_user_policy" "{user}" {{\n  user = aws_iam_user.{user}.name\n'
        f"  policy = jsonencode({{Statement = [{statements}]}})\n}}\n"
    )


def role(name, service="", extra=""):
    trust = f'Principal = {{Service = "{service}"}}' if service else "Principal = {AWS = aws_iam_user.chris.arn}"
    return (
        f'resource "aws_iam_role" "{name}" {{\n  assume_role_policy = jsonencode({{Statement = [{{Effect = "Allow", '
        f'Action = "sts:AssumeRole", {trust}}}]}})\n{extra}}}\n'
    )


ADMIN = '  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]\n'
DATA = 'resource "aws_s3_bucket" "secrets" {}\nresource "aws_dynamodb_table" "orders" {}\n'
READ = '  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]\n'


def test_a_plain_grant(tmp_path):
    r = search(
        tmp_path,
        'resource "aws_iam_user" "u" {}\n'
        + DATA
        + user_policy("u", '{Effect = "Allow", Action = "s3:GetObject", Resource = "*"}'),
        "aws_iam_user.u",
    )
    assert r.data() == {"aws_s3_bucket.secrets": "read"}


def test_assume_a_role_that_trusts_you(tmp_path):
    r = search(tmp_path, 'resource "aws_iam_user" "chris" {}\n' + DATA + role("ops", extra=ADMIN), "aws_iam_user.chris")
    assert "aws_iam_role.ops" in r.identities()
    assert r.data()["aws_dynamodb_table.orders"] == "admin"
    (hop,) = r.path("identity", "aws_iam_role.ops")
    assert hop.rule == "privesc-sts-001" and hop.confidence == "certain"


def test_pass_a_role_to_a_new_function(tmp_path):
    # PassRole + CreateFunction + InvokeFunction, to the role that trusts Lambda (not the one that trusts EC2)
    r = search(
        tmp_path,
        'resource "aws_iam_user" "dev" {}\n'
        + DATA
        + role("fn", "lambda.amazonaws.com", READ)
        + role("vm", "ec2.amazonaws.com", READ)
        + user_policy(
            "dev",
            '{Effect = "Allow", Action = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], '
            'Resource = "*"}',
        ),
        "aws_iam_user.dev",
    )
    assert "aws_iam_role.fn" in r.identities() and "aws_iam_role.vm" not in r.identities()
    assert r.path("identity", "aws_iam_role.fn")[0].rule == "privesc-lambda-001"


def test_rewriting_your_own_policy_is_admin(tmp_path):
    r = search(
        tmp_path,
        'resource "aws_iam_user" "raynor" {}\nresource "aws_iam_policy" "p" {\n'
        '  policy = jsonencode({Statement = [{Effect = "Allow", Action = ["iam:CreatePolicyVersion"], Resource = "*"}]})\n}\n'
        'resource "aws_iam_user_policy_attachment" "a" {\n  user = aws_iam_user.raynor.name\n'
        "  policy_arn = aws_iam_policy.p.arn\n}\n" + DATA,
        "aws_iam_user.raynor",
    )
    assert ("admin", "account") in r.gains
    assert r.data()["aws_s3_bucket.secrets"] == "admin"


def test_new_code_in_a_function_runs_as_its_role(tmp_path):
    r = search(
        tmp_path,
        'resource "aws_iam_user" "u" {}\n'
        + DATA
        + role("fnrole", "lambda.amazonaws.com", ADMIN)
        + 'resource "aws_lambda_function" "f" {\n  function_name = "f"\n  role = aws_iam_role.fnrole.arn\n}\n'
        + user_policy("u", '{Effect = "Allow", Action = ["lambda:UpdateFunctionCode"], Resource = "*"}'),
        "aws_iam_user.u",
    )
    assert "aws_iam_role.fnrole" in r.identities()


def test_an_access_key_in_configuration_it_can_read(tmp_path):
    r = search(
        tmp_path,
        'resource "aws_iam_user" "u" {}\nresource "aws_iam_user" "deployer" {}\n'
        'resource "aws_iam_access_key" "k" {\n  user = aws_iam_user.deployer.name\n}\n'
        'resource "aws_lambda_function" "f" {\n  function_name = "f"\n  environment {\n    variables = {\n'
        "      KEY = aws_iam_access_key.k.id\n      SECRET = aws_iam_access_key.k.secret\n    }\n  }\n}\n"
        + user_policy("u", '{Effect = "Allow", Action = ["lambda:GetFunctionConfiguration"], Resource = "*"}'),
        "aws_iam_user.u",
    )
    (hop,) = r.path("identity", "aws_iam_user.deployer")
    assert hop.rule == "credentials" and hop.confidence == "likely"


def test_deny_stops_it(tmp_path):
    r = search(
        tmp_path,
        'resource "aws_iam_user" "u" {}\n'
        + DATA
        + user_policy(
            "u",
            '{Effect = "Allow", Action = "s3:*", Resource = "*"}, {Effect = "Deny", Action = "s3:*", Resource = "*"}',
        ),
        "aws_iam_user.u",
    )
    assert r.data() == {}


def test_leaks_worst_first(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_iam_user" "reader" {}\nresource "aws_iam_user" "boss" {}\nresource "aws_iam_user" "idle" {}\n'
        + DATA
        + user_policy("reader", '{Effect = "Allow", Action = "s3:GetObject", Resource = "*"}')
        + user_policy("boss", '{Effect = "Allow", Action = "*", Resource = "*"}')
    )
    g = graph.build(tmp_path, ".")
    out = escalate.leaks(g, arch.build(g))
    assert [c.steps[1] for c in out] == ["aws_iam_user.boss", "aws_iam_user.reader"]  # idle gives nothing more
    assert out[0].entry == "boss: becomes the account's administrator" and out[0].severity == "critical"
    assert out[1].sinks == ["aws_s3_bucket.secrets"]


def ssh_host(extra: str) -> str:
    """An instance with a public IP, SSH open to the world, running as an admin role."""
    return (
        'resource "aws_vpc" "v" {}\nresource "aws_subnet" "pub" {\n  vpc_id = aws_vpc.v.id\n'
        "  map_public_ip_on_launch = true\n}\n"
        'resource "aws_security_group" "ssh" {\n  vpc_id = aws_vpc.v.id\n  ingress {\n    from_port = 22\n'
        '    to_port = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
        + role("box", "ec2.amazonaws.com", ADMIN)
        + 'resource "aws_iam_instance_profile" "box" {\n  role = aws_iam_role.box.name\n}\n'
        'resource "aws_instance" "box" {\n  subnet_id = aws_subnet.pub.id\n  associate_public_ip_address = true\n'
        "  vpc_security_group_ids = [aws_security_group.ssh.id]\n"
        "  iam_instance_profile = aws_iam_instance_profile.box.name\n" + extra + "}\n"
    )


def test_ssh_with_a_private_key_found_in_a_parameter(tmp_path):
    r = search(
        tmp_path,
        'resource "aws_iam_user" "u" {}\nresource "aws_key_pair" "k" {\n  public_key = "ssh-ed25519 AAAA"\n}\n'
        'resource "aws_ssm_parameter" "ssh_private_key" {\n  type = "SecureString"\n  value = "x"\n}\n'
        + ssh_host("  key_name = aws_key_pair.k.key_name\n")
        + user_policy("u", '{Effect = "Allow", Action = "ssm:GetParameter", Resource = "*"}'),
        "aws_iam_user.u",
    )
    hop = r.path("identity", "aws_iam_role.box")[-1]
    assert (hop.rule, hop.confidence) == ("ssh-found-key", "likely")
    assert ("control", "aws_instance.box") in r.gains


def test_ssh_with_a_password_set_in_user_data(tmp_path):
    r = search(
        tmp_path,
        'resource "aws_iam_user" "u" {}\n'
        + ssh_host('  user_data = "echo \\"ec2-user:hunter2\\" | chpasswd"\n')
        + user_policy("u", '{Effect = "Allow", Action = "ec2:DescribeInstanceAttribute", Resource = "*"}'),
        "aws_iam_user.u",
    )
    assert r.path("identity", "aws_iam_role.box")[-1].rule == "ssh-found-password"


def test_the_default_compute_account_adds_an_ssh_key_to_an_owner_s_vm(tmp_path):
    r = search(
        tmp_path,
        'data "google_compute_default_service_account" "default" {}\nresource "google_project" "p" {}\n'
        'resource "google_compute_instance" "dev" {\n  service_account {\n'
        '    email = data.google_compute_default_service_account.default.email\n    scopes = ["compute-rw"]\n  }\n}\n'
        'resource "google_service_account" "sa" {}\n'
        'resource "google_compute_instance" "admin" {\n  service_account {\n'
        '    email = google_service_account.sa.email\n    scopes = ["cloud-platform"]\n  }\n}\n'
        'resource "google_project_iam_member" "owner" {\n  role = "roles/owner"\n'
        '  member = "serviceAccount:${google_service_account.sa.email}"\n}\n'
        'resource "google_firestore_document" "user" {\n  database = "(default)"\n}\n',
        "google_compute_instance.dev",
    )
    (hop,) = r.path("identity", "google_service_account.sa")
    assert (hop.rule, hop.confidence) == ("gcp-lat-compute-instance-ssh-key-metadata", "likely")
    assert r.gains[("admin", "account")].confidence == "likely"
    assert r.data()["google_firestore_document.user"] == "admin"  # the owner's data, drawn or not
