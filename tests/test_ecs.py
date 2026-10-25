"""ECS: a service runs as its task definition's task role, and on EC2 it runs on its cluster's hosts, whose
exposure (on the ports its containers publish) reaches it and whose role its containers can reach too."""

from test_chains import BUCKETS, NET, sg

from terrahunter import arch, chains, graph

ROLES = (
    'resource "aws_iam_role" "task" {}\nresource "aws_iam_role" "host" {}\n'
    'resource "aws_iam_role_policy" "t" {\n  role = aws_iam_role.task.id\n  policy = <<EOF\n'
    '{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "${aws_s3_bucket.customer_exports.arn}"}]}\nEOF\n}\n'
    'resource "aws_iam_role_policy" "h" {\n  role = aws_iam_role.host.id\n  policy = <<EOF\n'
    '{"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}\nEOF\n}\n'
    'resource "aws_iam_instance_profile" "host" {\n  role = aws_iam_role.host.name\n}\n'
)


def task(name: str, ports: str = "[{ containerPort = 80, hostPort = 80 }]", mode: str = "bridge") -> str:
    return (
        f'resource "aws_ecs_task_definition" "{name}" {{\n  network_mode = "{mode}"\n'
        "  task_role_arn = aws_iam_role.task.arn\n"
        f'  container_definitions = jsonencode([{{ name = "app", image = "x", portMappings = {ports} }}])\n}}\n'
    )


CLUSTER = 'resource "aws_ecs_cluster" "c" {\n  name = "c"\n}\n'
HOSTS = (
    sg("hosts", 80)
    + 'resource "aws_launch_template" "lt" {\n  vpc_security_group_ids = [aws_security_group.hosts.id]\n'
    "  iam_instance_profile {\n    name = aws_iam_instance_profile.host.name\n  }\n"
    "  network_interfaces {\n    associate_public_ip_address = true\n  }\n"
    '  user_data = base64encode("echo ECS_CLUSTER=${aws_ecs_cluster.c.name} >> /etc/ecs/ecs.config")\n}\n'
    'resource "aws_autoscaling_group" "asg" {\n  vpc_zone_identifier = [aws_subnet.pub.id]\n'
    "  launch_template {\n    id = aws_launch_template.lt.id\n  }\n}\n"
)


def service(name: str, td: str, extra: str = "") -> str:
    return (
        f'resource "aws_ecs_service" "{name}" {{\n  cluster = aws_ecs_cluster.c.id\n'
        f"  task_definition = aws_ecs_task_definition.{td}.arn\n{extra}}}\n"
    )


def build(tmp_path, text):
    (tmp_path / "main.tf").write_text(text)
    g = graph.build(tmp_path, ".")
    m = arch.build(g)
    return m, chains.build(g, m)


def test_a_service_on_public_hosts_on_its_published_port(tmp_path):
    m, r = build(
        tmp_path,
        NET
        + BUCKETS
        + ROLES
        + CLUSTER
        + HOSTS
        + task("web")
        + task("worker", "[]")
        + service("web", "web")
        + service("worker", "worker"),
    )
    conns = {(c.source, c.target, c.label) for c in m.connections}
    assert ("aws_ecs_service.web", "aws_iam_role.task", "runs as") in conns
    assert {
        ("aws_ecs_service.web", "aws_launch_template.lt", "runs on"),
        ("aws_ecs_service.web", "aws_autoscaling_group.asg", "runs on"),
    } <= conns
    entries = {c.steps[1] for c in r.chains}
    assert entries == {"aws_ecs_service.web"}  # the worker publishes no port: not reachable through the host
    by_identity = {c.steps[-1]: c for c in r.chains}
    assert by_identity["aws_iam_role.task"].sinks == ["aws_s3_bucket.customer_exports"]
    host = by_identity["aws_iam_role.host"]  # from the container, the host's metadata service
    assert sorted(host.sinks) == ["aws_s3_bucket.customer_exports", "aws_s3_bucket.logs"]
    assert any("from the container" in h for h in host.hops)


def test_through_a_load_balancer(tmp_path):
    lb = (
        sg("lb", 443) + 'resource "aws_lb" "front" {\n  security_groups = [aws_security_group.lb.id]\n}\n'
        'resource "aws_lb_target_group" "tg" {}\n'
        'resource "aws_lb_listener" "l" {\n  load_balancer_arn = aws_lb.front.arn\n'
        "  default_action {\n    target_group_arn = aws_lb_target_group.tg.arn\n  }\n}\n"
    )
    _, r = build(
        tmp_path,
        NET
        + BUCKETS
        + ROLES
        + CLUSTER
        + lb
        + task("app", "[]")
        + service(
            "app",
            "app",
            '  launch_type = "FARGATE"\n  load_balancer {\n    target_group_arn = aws_lb_target_group.tg.arn\n  }\n',
        ),
    )
    (c,) = r.chains
    assert c.steps == ["internet", "aws_lb.front", "aws_ecs_service.app", "aws_iam_role.task"]  # Fargate: no host


def test_awsvpc_with_a_public_ip(tmp_path):
    _, r = build(
        tmp_path,
        NET
        + BUCKETS
        + ROLES
        + CLUSTER
        + sg("svc", 8080)
        + task("api", "[{ containerPort = 8080 }]", "awsvpc")
        + service(
            "api",
            "api",
            '  launch_type = "FARGATE"\n  network_configuration {\n    subnets = [aws_subnet.pub.id]\n'
            "    security_groups = [aws_security_group.svc.id]\n    assign_public_ip = true\n  }\n",
        ),
    )
    (c,) = r.chains
    assert c.steps[:2] == ["internet", "aws_ecs_service.api"] and "assign_public_ip" in c.entry


PINNED_HOSTS = sg("hosts", 80) + "".join(
    f'resource "aws_instance" "{n}" {{\n  subnet_id = aws_subnet.pub.id\n  associate_public_ip_address = true\n'
    f"  vpc_security_group_ids = [aws_security_group.hosts.id]\n  iam_instance_profile = aws_iam_instance_profile.host.name\n"
    '  user_data = "echo ECS_CLUSTER=${aws_ecs_cluster.c.name} >> /etc/ecs/ecs.config"\n}\n'
    for n in ("front", "back")
)


def test_a_service_pinned_to_one_host_runs_only_there(tmp_path):
    pin = '  placement_constraints {\n    type = "memberOf"\n    expression = "ec2InstanceId == ${aws_instance.front.id}"\n  }\n'
    m, r = build(
        tmp_path,
        NET
        + BUCKETS
        + ROLES
        + CLUSTER
        + PINNED_HOSTS
        + task("web")
        + task("db", "[]")
        + service("web", "web", pin)
        + service("db", "db"),
    )
    conns = {(c.source, c.target, c.label) for c in m.connections}
    assert ("aws_ecs_service.web", "aws_instance.front", "runs on") in conns
    assert ("aws_ecs_service.web", "aws_instance.back", "runs on") not in conns
    # the other host runs only the db, which publishes nothing: port 80 is open there, but nothing listens
    assert "aws_instance.back" not in {c.steps[1] for c in r.chains}
    assert "aws_ecs_service.web" in {c.steps[1] for c in r.chains}
