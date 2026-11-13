import json
import threading

from opgraph.facts import (
    Fact,
    FactStore,
    credential,
    endpoint,
    finding,
    host,
    note,
    param,
    service,
    tech,
)


def test_dedup_and_merge() -> None:
    store = FactStore()
    assert len(store.add([service("10.0.0.1", 80, name="http")])) == 1
    assert store.add([service("10.0.0.1", 80, product="nginx")]) == []
    svc = store.get("service:10.0.0.1|80|tcp")
    assert svc is not None
    assert svc.get("name") == "http" and svc.get("product") == "nginx"
    # empty values never erase known ones
    store.add([service("10.0.0.1", 80, product="")])
    assert store.get("service:10.0.0.1|80|tcp").get("product") == "nginx"  # type: ignore[union-attr]
    assert len(store) == 1


def test_newer_value_wins() -> None:
    store = FactStore()
    store.add([endpoint("http://h/a", status=200)])
    store.add([endpoint("http://h/a", status=302)])
    assert store.query("endpoint")[0].get("status") == 302


def test_query_by_key_part_and_attr() -> None:
    store = FactStore()
    store.add(
        [
            service("10.0.0.1", 80, name="http"),
            service("10.0.0.1", 21, name="ftp"),
            service("10.0.0.2", 80, name="http"),
        ]
    )
    assert len(store.query("service", host="10.0.0.1")) == 2
    assert len(store.query("service", port=80)) == 2
    assert len(store.query("service", name="ftp", host="10.0.0.1")) == 1
    assert store.query("service", name="ssh") == []
    assert len(store.query()) == 3


def test_endpoint_normalisation_dedups() -> None:
    store = FactStore()
    store.add([endpoint("HTTP://H:80/a?x=1"), endpoint("http://h/a#frag")])
    assert [f.id for f in store] == ["endpoint:http://h/a"]


def test_graph_chain() -> None:
    store = FactStore()
    url = "http://10.0.0.1:8080/login"
    store.add(
        [
            host("10.0.0.1"),
            service("10.0.0.1", 8080, name="http"),
            endpoint(url, status=200),
            param(url, "body", "username"),
            finding("sqli", url, rationale="error on quote"),
        ]
    )
    chain = store.chain(f"finding:sqli|{url}")
    assert [f.kind for f in chain] == ["host", "service", "endpoint", "finding"]
    kids = {f.kind for f in store.children(f"endpoint:{url}")}
    assert kids == {"param", "finding"}


def test_subscribe_and_unsubscribe() -> None:
    store = FactStore()
    events: list[tuple[str, str]] = []
    unsubscribe = store.subscribe(lambda event, fact: events.append((event, fact.id)))
    store.add([host("10.0.0.1")])
    store.add([host("10.0.0.1", os="linux")])
    store.add([host("10.0.0.1", os="linux")])  # no change -> no event
    unsubscribe()
    store.add([host("10.0.0.2")])
    assert events == [("new", "host:10.0.0.1"), ("updated", "host:10.0.0.1")]


def test_jsonl_round_trip() -> None:
    store = FactStore()
    store.add([service("10.0.0.1", 22, name="ssh"), note("check ssh later")])
    rows = [Fact.from_dict(json.loads(line)) for line in store.to_jsonl().splitlines()]
    rebuilt = FactStore()
    rebuilt.add(rows)
    assert {f.id: dict(f.attrs) for f in rebuilt} == {f.id: dict(f.attrs) for f in store}


def test_attrs_are_immutable() -> None:
    fact = host("10.0.0.1", os="linux")
    try:
        fact.attrs["os"] = "windows"  # type: ignore[index]
    except TypeError:
        pass
    else:
        raise AssertionError("attrs should be read-only")


def test_helpers() -> None:
    assert note("x").target_derived is False
    assert finding("xss", "http://h/").get("status") == "proposed"
    assert tech("http://h:8080/a", "Flask").id == "tech:http://h:8080|flask"
    cred = credential("http://h:8080/login", "admin", "s3cret")
    assert cred.get("secret") == "s3cret" and cred.parent == "service:h|8080|tcp"


def test_thread_safety() -> None:
    store = FactStore()

    def worker(n: int) -> None:
        store.add([service("10.0.0.1", port) for port in range(n, n + 50)])

    threads = [threading.Thread(target=worker, args=(i * 10,)) for i in range(100)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(store) == len({p for i in range(100) for p in range(i * 10, i * 10 + 50)})


def test_define_custom_kind() -> None:
    import pytest

    from opgraph.facts import define_kind

    define_kind("vhost", ("ip", "name"))
    store = FactStore()
    store.add([Fact("vhost", ("10.0.0.1", "dev.acme.test"), {"status": 200})])
    assert store.query("vhost", name="dev.acme.test")[0].get("ip") == "10.0.0.1"
    with pytest.raises(ValueError):
        define_kind("host", ("x",))


def test_short_keys_do_not_crash() -> None:
    from opgraph.render import world

    store = FactStore()
    store.add([Fact("service", ("10.0.0.5", "x"), {"name": "http"})])
    assert store.query("service")[0].get("proto") is None
    assert "SVC x/None" in world(store)
