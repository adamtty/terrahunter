"""Check by hand: what a path rests on that the Terraform doesn't show, with where to look."""

from test_chains import NET, ROLE, instance, paths, sg


def by_kind(r, kind):
    return {k.about: k for k in r.checks if k.kind == kind}


def test_a_shell_over_ssh_needs_a_login_and_a_web_app_its_code(tmp_path):
    r = paths(
        tmp_path,
        NET
        + ROLE
        + sg("open", 22, 80)
        + 'resource "aws_s3_bucket" "data" {}\n'
        + instance(
            "web",
            "pub",
            "open",
            '  key_name = "ops"\n  associate_public_ip_address = true\n'
            "  iam_instance_profile = aws_iam_instance_profile.app.name\n",
        ),
    )
    assert "aws_instance.web" in by_kind(r, "login") or "aws_instance.web" in by_kind(r, "code")
    for c in r.chains:
        assert c.checks, c.kind  # every path says what it rests on


def test_a_function_s_code_is_pointed_at(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("def handler(event, context): ...\n")
    r = paths(
        tmp_path,
        'resource "aws_iam_role" "fn" {}\n'
        'data "archive_file" "src" {\n  type = "zip"\n  source_dir = "${path.module}/app"\n'
        '  output_path = "${path.module}/build/app.zip"\n}\n'
        'resource "aws_lambda_function" "api" {\n  function_name = "api"\n  role = aws_iam_role.fn.arn\n'
        "  filename = data.archive_file.src.output_path\n}\n"
        'resource "aws_lambda_function_url" "u" {\n  function_name = aws_lambda_function.api.function_name\n'
        '  authorization_type = "NONE"\n}\n'
        'resource "aws_iam_role_policy" "p" {\n  role = aws_iam_role.fn.id\n'
        '  policy = jsonencode({Statement = [{Effect = "Allow", Action = "s3:*", Resource = "*"}]})\n}\n'
        'resource "aws_s3_bucket" "data" {}\n',
    )
    code = by_kind(r, "code")["aws_lambda_function.api"]
    assert "app" in code.where and "isn't in the folders" not in code.question


def test_deploy_time_scripts_and_boot_scripts_on_the_path(tmp_path):
    r = paths(
        tmp_path,
        NET + ROLE + sg("open", 22) + 'resource "aws_iam_user" "admin" {}\n'
        'resource "aws_iam_access_key" "k" {\n  user = aws_iam_user.admin.name\n}\n'
        'resource "aws_s3_bucket" "scratch_files" {\n  bucket = "scratch-files"\n}\n'
        + instance(
            "box",
            "pub",
            "open",
            '  key_name = "ops"\n  associate_public_ip_address = true\n'
            "  iam_instance_profile = aws_iam_instance_profile.app.name\n"
            '  user_data = "aws s3 rb s3://scratch-files --force"\n'
            '  provisioner "file" {\n    content = "${aws_iam_access_key.k.secret}"\n    destination = "/tmp/k"\n  }\n',
        )
        + 'resource "aws_iam_role_policy" "p" {\n  role = aws_iam_role.app.id\n'
        '  policy = jsonencode({Statement = [{Effect = "Allow", Action = "s3:*", Resource = "*"}]})\n}\n',
    )
    script = by_kind(r, "script")["aws_instance.box"]
    assert "file" in script.question and "aws_iam_access_key.k" in script.question
    assert "aws_s3_bucket.scratch_files" in by_kind(r, "boot")
