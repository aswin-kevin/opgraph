import pytest

from opgraph.scope import OutOfScope, Scope
from opgraph.targets import canonical_ip, normalize_url, parse_target

FAKE_DNS = {
    "app.acme.test": "10.10.10.5",
    "meta.acme-cdn.example": "169.254.169.254",
    "evil.example": "203.0.113.9",
    "app.acme.test.evil.example": "203.0.113.9",
    "rebind.acme.test": "169.254.169.254",
}


def fake_resolver(host: str) -> str:
    if host not in FAKE_DNS:
        raise OSError("NXDOMAIN")
    return FAKE_DNS[host]


@pytest.fixture
def scope() -> Scope:
    return Scope(nets=["10.10.10.0/24"], domains=["acme.test"], resolver=fake_resolver)


# Every one of these actually points at 169.254.169.254 or evil.example.
BYPASSES = [
    "http://2852039166/latest/meta-data/",  # decimal IP
    "http://0xa9fea9fe/",  # hex IP
    "http://0251.0376.0251.0376/",  # octal IP
    "http://169.254.43518/",  # short-form IP
    "http://[::ffff:a9fe:a9fe]/",  # IPv4-mapped IPv6
    "http://app.acme.test.evil.example/",  # in-scope name as a substring
    "http://meta.acme-cdn.example/",  # DNS points outside
    "http://app.acme.test@evil.example/",  # userinfo trick
    "http://rebind.acme.test/",  # in-scope domain resolving to metadata
]

LEGIT = [
    "http://app.acme.test/login",
    "https://app.acme.test/api?id=1",
    "http://10.10.10.5:8080/",
    "10.10.10.5",
    "10.10.10.5:22",
    "APP.ACME.TEST.",
]


@pytest.mark.parametrize("target", BYPASSES)
def test_bypasses_are_blocked(scope: Scope, target: str) -> None:
    with pytest.raises(OutOfScope):
        scope.check(target)


@pytest.mark.parametrize("target", LEGIT)
def test_legit_targets_are_allowed(scope: Scope, target: str) -> None:
    assert scope.allows(target)


def test_checked_target_pins_ip(scope: Scope) -> None:
    checked = scope.check("http://app.acme.test/x")
    assert checked.ip == "10.10.10.5"
    assert checked.host == "app.acme.test"


def test_resolver_called_once_per_host() -> None:
    calls = []

    def resolver(host: str) -> str:
        calls.append(host)
        return "10.10.10.5"

    s = Scope(domains=["acme.test"], resolver=resolver)
    s.check("http://app.acme.test/a")
    s.check("http://app.acme.test/b")
    assert calls == ["app.acme.test"]


def test_exclude_wins() -> None:
    s = Scope(
        nets=["10.10.10.0/24"],
        domains=["acme.test"],
        exclude=["10.10.10.1", "admin.acme.test"],
        resolver=fake_resolver,
    )
    assert not s.allows("10.10.10.1")
    assert not s.allows("http://admin.acme.test/")
    assert not s.allows("http://x.admin.acme.test/")
    assert s.allows("10.10.10.2")


def test_port_restriction() -> None:
    s = Scope(nets=["10.10.10.0/24"], ports=[80, 8080])
    assert s.allows("http://10.10.10.5/")  # default port 80
    assert s.allows("10.10.10.5:8080")
    assert not s.allows("https://10.10.10.5/")  # default port 443
    assert not s.allows("10.10.10.5:22")
    assert s.allows("10.10.10.5")  # bare host: no port to check


def test_link_local_allowed_when_explicit() -> None:
    assert Scope(nets=["169.254.169.254/32"]).allows("http://169.254.169.254/")


def test_ipv6() -> None:
    s = Scope(nets=["2001:db8::/32"])
    assert s.allows("http://[2001:db8::1]:8080/")
    assert s.allows("2001:db8::5")
    assert not s.allows("http://[2001:db9::1]/")


@pytest.mark.parametrize("bad", ["", "  ", "http://", "http://a b/", "host:99999", "a\x00b"])
def test_garbage_is_blocked(scope: Scope, bad: str) -> None:
    with pytest.raises(OutOfScope):
        scope.check(bad)


def test_unresolvable_is_blocked(scope: Scope) -> None:
    with pytest.raises(OutOfScope, match="cannot resolve"):
        scope.check("http://nope.acme.test/")


def test_from_dict_and_file(tmp_path) -> None:
    data = {"nets": ["127.0.0.1/32"], "domains": ["localhost"], "exclude": [], "ports": None}
    assert Scope.from_dict(data).allows("http://127.0.0.1:8000/")
    path = tmp_path / "scope.toml"
    path.write_text('nets = ["127.0.0.1/32"]\nports = [8000]\n')
    s = Scope.from_file(path)
    assert s.allows("http://127.0.0.1:8000/")
    assert not s.allows("http://127.0.0.1:9000/")
    assert s.to_dict()["ports"] == [8000]


def test_audit_command(scope: Scope) -> None:
    assert scope.audit_command("curl -s http://app.acme.test/ | grep x") == []
    warnings = scope.audit_command("curl http://2852039166/ && nmap -iL targets.txt evil.example")
    assert len(warnings) == 2


def test_parse_and_normalize() -> None:
    t = parse_target("HTTP://User:pw@Example.TEST:8080/a?b#c")
    assert (t.scheme, t.host, t.port, t.path) == ("http", "example.test", 8080, "/a")
    assert normalize_url("HTTP://Example.TEST:80") == "http://example.test/"
    assert normalize_url("https://h:8443/x?y=1#f") == "https://h:8443/x"
    assert normalize_url("https://h:8443/x?y=1", keep_query=True) == "https://h:8443/x?y=1"
    assert normalize_url("http://[::1]:8080/") == "http://[::1]:8080/"
    assert str(canonical_ip("2852039166")) == "169.254.169.254"
    assert canonical_ip("example.test") is None


@pytest.mark.parametrize(
    "target",
    [
        "http://[fd00:ec2::254]/",  # AWS IMDS over IPv6
        "http://[64:ff9b::a9fe:a9fe]/",  # NAT64 form of 169.254.169.254
        "http://[::a9fe:a9fe]/",  # IPv4-compatible form
        "http://x%2eacme.test/",  # percent-encoding in the host
        "http://\uff41pp.acme.test/",  # Unicode host
    ],
)
def test_more_bypasses_blocked(scope: Scope, target: str) -> None:
    assert not scope.allows(target)


def test_out_of_domain_names_are_never_resolved() -> None:
    asked: list[str] = []

    def resolver(host: str) -> str:
        asked.append(host)
        return "10.10.10.5"

    s = Scope(nets=["10.10.10.0/24"], domains=["acme.test"], resolver=resolver)
    assert not s.allows("http://secret-data.attacker.example/")
    assert s.audit_command("curl http://leak.attacker.example/") != []
    assert asked == []


@pytest.mark.parametrize("answer", ["127.0.0.1", "0.0.0.0", "::1", "224.0.0.1"])
def test_domain_resolving_to_loopback_or_reserved_blocked(answer: str) -> None:
    s = Scope(domains=["acme.test"], resolver=lambda h: answer)
    with pytest.raises(OutOfScope, match="loopback/reserved"):
        s.check("http://app.acme.test/")


def test_loopback_allowed_when_listed() -> None:
    s = Scope(nets=["127.0.0.1/32"], domains=["localhost"], resolver=lambda h: "127.0.0.1")
    assert s.allows("http://localhost:8000/")


def test_check_resolver_override_does_not_mutate_scope() -> None:
    s = Scope(domains=["acme.test"])
    assert s.check("http://app.acme.test/", resolver=lambda h: "10.0.0.9").ip == "10.0.0.9"
    assert s.resolver is None
