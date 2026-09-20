"""POST /sbom 的端到端测试。

覆盖：先审计后导出的 409 短路、按包名排序、PURL、依赖名（仅已激活、
去重排序）、元数据透传与缺失 warnings（不阻断）、按锁定版本取元数据、
PEP 503 规范化、marker 激活、确定性排序，以及 422（非法 sha256/url、
非法快照/锁/根包/多余字段）与既有接口对 metadata 字段的兼容性。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.sbom import package_url

client = TestClient(app)

ENV = {
    "python_version": "3.11",
    "sys_platform": "linux",
    "platform_machine": "x86_64",
}
WIN_ENV = {
    "python_version": "3.11",
    "sys_platform": "win32",
    "platform_machine": "AMD64",
}


def c(version, deps=None, **meta_kwargs):
    entry = {"version": version, "dependencies": deps or []}
    if meta_kwargs:
        entry["metadata"] = meta_kwargs
    return entry


def d(name, spec="", marker=""):
    return {"name": name, "specifier": spec, "marker": marker}


def query(repo, lock, *, root="app", env=None, **overrides):
    body = {
        "repository": repo,
        "root": root,
        "target_environment": env or ENV,
        "current_lock": lock,
    }
    body.update(overrides)
    return client.post("/sbom", json=body)


def sbom(repo, lock, **kw):
    r = query(repo, lock, **kw)
    assert r.status_code == 200, r.text
    return r.json()


def by_name(body):
    return {p["name"]: p for p in body["packages"]}


# --------------------------------------------------------------------- #
# 1. 基础导出：名称/版本/PURL/依赖/元数据，按包名排序
# --------------------------------------------------------------------- #
def test_basic_sbom_export_sorted_packages():
    repo = {
        "app": [c("1.0.0", [d("web-framework", ">=2.0"), d("auth-lib")],
                  source_url="https://x/app.tgz",
                  sha256="a" * 64,
                  license="Apache-2.0")],
        "web-framework": [c("3.2.0", [d("shared-util", ">=1.0,<3.0")],
                            license="BSD-3-Clause")],
        "auth-lib": [c("0.9.0", [d("shared-util", "<2.0")],
                       sha256="b" * 64, license="MIT")],
        "shared-util": [c("2.0.0"), c("1.5.0", license="MIT")],
    }
    lock = {"app": "1.0.0", "auth-lib": "0.9.0",
            "shared-util": "1.5.0", "web-framework": "3.2.0"}
    body = sbom(repo, lock)
    assert body["status"] == "ok"
    assert body["root"] == "app"
    assert [p["name"] for p in body["packages"]] == [
        "app", "auth-lib", "shared-util", "web-framework"
    ]

    app_pkg = by_name(body)["app"]
    assert app_pkg["version"] == "1.0.0"
    assert app_pkg["purl"] == "pkg:pypi/app@1.0.0"
    assert app_pkg["dependencies"] == ["auth-lib", "web-framework"]
    assert app_pkg["metadata"] == {
        "source_url": "https://x/app.tgz",
        "sha256": "a" * 64,
        "license": "Apache-2.0",
    }

    assert by_name(body)["web-framework"]["dependencies"] == ["shared-util"]
    assert by_name(body)["shared-util"]["dependencies"] == []


def test_purl_unit_forms():
    assert package_url("some-pkg", "1.2.3") == "pkg:pypi/some-pkg@1.2.3"
    assert package_url("some-pkg", "2.0rc1") == "pkg:pypi/some-pkg@2.0rc1"
    # PEP 440 epoch 落在 PURL pchar 字符集内，保持原样、确定性输出。
    assert package_url("foo", "1!2.0") == "pkg:pypi/foo@1!2.0"


# --------------------------------------------------------------------- #
# 2. 缺失元数据：只形成 warnings，不阻断导出
# --------------------------------------------------------------------- #
def test_missing_metadata_produces_warnings_but_exports():
    repo = {
        "app": [c("1.0", [d("liba")], license="MIT")],
        "liba": [c("1.0")],  # 三项全缺
    }
    body = sbom(repo, {"app": "1.0", "liba": "1.0"})
    app_pkg = by_name(body)["app"]
    assert app_pkg["metadata"] == {"source_url": None, "sha256": None,
                                   "license": "MIT"}
    liba = by_name(body)["liba"]
    assert liba["metadata"] == {"source_url": None, "sha256": None,
                                "license": None}

    # warnings 按包名排序；缺失字段按固定枚举次序（license、sha256、source_url）。
    assert body["warnings"] == [
        {"name": "app", "missing": ["sha256", "source_url"]},
        {"name": "liba", "missing": ["license", "sha256", "source_url"]},
    ]


def test_empty_string_metadata_counts_as_missing():
    repo = {"app": [{"version": "1.0", "dependencies": [],
                     "metadata": {"source_url": "  ", "sha256": "",
                                  "license": ""}}]}
    body = sbom(repo, {"app": "1.0"})
    assert body["packages"][0]["metadata"] == {
        "source_url": None, "sha256": None, "license": None
    }
    assert body["warnings"] == [
        {"name": "app", "missing": ["license", "sha256", "source_url"]}
    ]


def test_full_metadata_means_no_warning():
    repo = {"app": [c("1.0", [],
                      source_url="https://x/a", sha256="a" * 64,
                      license="MIT")]}
    body = sbom(repo, {"app": "1.0"})
    assert body["warnings"] == []


# --------------------------------------------------------------------- #
# 3. 元数据取锁定版本的候选（而非最新版本）
# --------------------------------------------------------------------- #
def test_metadata_taken_from_locked_candidate():
    repo = {
        "app": [c("1.0", [d("liba")])],
        "liba": [
            c("2.0", license="NEW"),
            c("1.0", license="OLD", sha256="c" * 64),
        ],
    }
    body = sbom(repo, {"app": "1.0", "liba": "1.0"})
    liba = by_name(body)["liba"]
    assert liba["version"] == "1.0"
    assert liba["purl"] == "pkg:pypi/liba@1.0"
    assert liba["metadata"]["license"] == "OLD"
    assert liba["metadata"]["sha256"] == "c" * 64
    assert liba["metadata"]["source_url"] is None


def test_sha256_uppercase_normalized_to_lowercase():
    repo = {"app": [c("1.0", sha256="ABCDEF0123456789" * 4, license="MIT")]}
    body = sbom(repo, {"app": "1.0"})
    assert body["packages"][0]["metadata"]["sha256"] == "abcdef0123456789" * 4


# --------------------------------------------------------------------- #
# 4. 依赖名：PEP 503 规范化、去重、仅已激活
# --------------------------------------------------------------------- #
def test_dependencies_are_canonical_deduped_and_sorted():
    repo = {
        "app": [c("1.0", [d("Some_Lib", ">=1.0"), d("some.lib", "<2.0")])],
        "some-lib": [c("1.0")],
    }
    body = sbom(repo, {"app": "1.0", "some-lib": "1.0"})
    app_pkg = body["packages"][0]
    assert app_pkg["dependencies"] == ["some-lib"]
    assert app_pkg["purl"] == "pkg:pypi/app@1.0"
    assert by_name(body)["some-lib"]["purl"] == "pkg:pypi/some-lib@1.0"


def test_inactive_marker_dependencies_excluded():
    repo = {
        "app": [c("1.0", [
            d("linux-thing", marker="sys_platform == 'linux'"),
            d("win-thing", marker="sys_platform == 'win32'"),
        ])],
        "linux-thing": [c("1.0")],
        "win-thing": [c("1.0")],
    }
    lock = {"app": "1.0", "linux-thing": "1.0"}
    body = sbom(repo, lock, env=ENV)
    assert by_name(body)["app"]["dependencies"] == ["linux-thing"]
    assert list(by_name(body)) == ["app", "linux-thing"]

    # 同一把锁在 win32 下审计失败（linux-thing 不可达 + win-thing 缺失）：
    # 409，不导出。
    r = query(repo, lock, env=WIN_ENV)
    assert r.status_code == 409
    types = {i["type"] for i in r.json()["issues"]}
    assert types == {"missing", "extraneous"}
    assert "packages" not in r.json()


def test_pep503_root_name_normalized_in_output():
    repo = {
        "Some_Root": [c("1.0", [d("DEP_X")])],
        "dep-x": [c("1.0")],
    }
    body = sbom(repo, {"some-root": "1.0", "dep-x": "1.0"}, root="Some_Root")
    assert body["root"] == "some-root"
    assert [p["name"] for p in body["packages"]] == ["dep-x", "some-root"]
    assert by_name(body)["some-root"]["purl"] == "pkg:pypi/some-root@1.0"


# --------------------------------------------------------------------- #
# 5. 确定性：与包键、锁键顺序无关
# --------------------------------------------------------------------- #
def test_deterministic_across_input_ordering():
    repo = {
        "app": [c("1.0", [d("zz-lib"), d("aa-lib"), d("mm-lib")],
                  license="MIT")],
        "zz-lib": [c("1.0", [d("common")])],
        "aa-lib": [c("1.0", [d("common")])],
        "mm-lib": [c("1.0", [d("common")])],
        "common": [c("1.0")],
    }
    lock = {"app": "1.0", "zz-lib": "1.0", "aa-lib": "1.0",
            "mm-lib": "1.0", "common": "1.0"}
    body1 = sbom(repo, lock)
    body2 = sbom(
        dict(reversed(list(repo.items()))),
        dict(reversed(list(lock.items()))),
    )
    assert body1 == body2
    assert [p["name"] for p in body1["packages"]] == [
        "aa-lib", "app", "common", "mm-lib", "zz-lib"
    ]
    assert by_name(body1)["app"]["dependencies"] == [
        "aa-lib", "mm-lib", "zz-lib"
    ]


# --------------------------------------------------------------------- #
# 6. 锁无效：409，携带与 /audit-lock 一致的问题，不导出
# --------------------------------------------------------------------- #
def test_invalid_lock_returns_409_with_audit_issues_and_no_document():
    repo = {
        "app": [c("1.0", [d("needs-thing"), d("old-lib", ">=2.0")])],
        "old-lib": [c("1.0"), c("2.0")],
        "stale": [c("1.0")],
    }
    lock = {"app": "1.0", "old-lib": "1.0", "stale": "1.0"}
    r = query(repo, lock)
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "invalid_lock"
    assert [(i["type"], i["name"]) for i in body["issues"]] == [
        ("missing", "needs-thing"),
        ("constraint_mismatch", "old-lib"),
        ("extraneous", "stale"),
    ]
    assert "packages" not in body and "warnings" not in body


def test_409_issues_match_audit_lock_endpoint():
    repo = {"app": [c("1.0", [d("libx")])], "libx": [c("1.0"), c("2.0")]}
    body = {"repository": repo, "root": "app", "target_environment": ENV,
            "current_lock": {"app": "1.0", "libx": "3.0"}}
    audit_body = client.post("/audit-lock", json=body).json()
    sbom_body = client.post("/sbom", json=body).json()
    assert sbom_body["issues"] == audit_body["issues"]


# --------------------------------------------------------------------- #
# 7. 422：非法元数据 / 快照 / 锁 / 根包 / 多余字段
# --------------------------------------------------------------------- #
def test_bad_sha256_422():
    repo = {"app": [c("1.0", sha256="too-short", license="MIT")]}
    r = query(repo, {"app": "1.0"})
    assert r.status_code == 422
    message = r.json()["message"]
    assert r.json()["status"] == "invalid_snapshot"
    assert "sha256" in message and "app==1.0" in message


def test_bad_source_url_422():
    repo = {"app": [c("1.0", source_url="ftp://example/x")]}
    r = query(repo, {"app": "1.0"})
    assert r.status_code == 422
    message = r.json()["message"]
    assert "source_url" in message and "http/https" in message


def test_relative_source_url_422():
    repo = {"app": [c("1.0", source_url="/just/a/path")]}
    r = query(repo, {"app": "1.0"})
    assert r.status_code == 422


def test_unknown_metadata_field_422():
    body = {
        "repository": {"app": [{"version": "1.0", "dependencies": [],
                                "metadata": {"license": "MIT", "homepage": "x"}}]},
        "root": "app",
        "target_environment": ENV,
        "current_lock": {"app": "1.0"},
    }
    assert client.post("/sbom", json=body).status_code == 422


def test_bad_snapshot_422():
    r = query({"app": [c("oops")]}, {"app": "1.0"})
    assert r.status_code == 422
    assert r.json()["status"] == "invalid_snapshot"


def test_bad_lock_version_422():
    r = query({"app": [c("1.0")]}, {"app": "not-a-version"})
    assert r.status_code == 422
    assert "PEP 440" in r.json()["message"]


def test_unknown_root_422():
    r = query({"app": [c("1.0")]}, {"app": "1.0"}, root="missing")
    assert r.status_code == 422
    assert "missing" in r.json()["message"]


def test_extra_top_level_field_forbidden_422():
    r = query({"app": [c("1.0")]}, {"app": "1.0"}, unknown=1)
    assert r.status_code == 422


# --------------------------------------------------------------------- #
# 8. 既有接口兼容：metadata 字段对 /resolve 等是可选的，/audit-lock 禁 target
# --------------------------------------------------------------------- #
def test_metadata_accepted_but_unused_by_other_endpoints():
    repo = {
        "app": [c("1.0", [d("libx")], license="MIT", sha256="a" * 64)],
        "libx": [c("1.0")],
    }
    base = {"repository": repo, "root": "app", "target_environment": ENV}

    r = client.post("/resolve", json=base)
    assert r.status_code == 200
    assert r.json()["locked"] == {"app": "1.0", "libx": "1.0"}

    lock = {"app": "1.0", "libx": "1.0"}
    r = client.post("/audit-lock", json={**base, "current_lock": lock})
    assert r.status_code == 200 and r.json()["valid"] is True

    r = client.post(
        "/dependency-paths", json={**base, "current_lock": lock, "target": "libx"}
    )
    assert r.status_code == 200
    assert r.json()["paths"] == [["app", "libx"]]


def test_duplicate_version_with_conflicting_metadata_422():
    repo = {"app": [
        {"version": "1.0", "dependencies": [], "metadata": {"license": "MIT"}},
        {"version": "1.0", "dependencies": [], "metadata": {"license": "GPL-2.0"}},
    ]}
    r = query(repo, {"app": "1.0"})
    assert r.status_code == 422
    assert "元数据不一致" in r.json()["message"]


def test_duplicate_version_with_identical_metadata_merged():
    repo = {"app": [
        {"version": "1.0", "dependencies": [], "metadata": {"license": "MIT"}},
        {"version": "1.0", "dependencies": [], "metadata": {"license": "MIT"}},
    ]}
    body = sbom(repo, {"app": "1.0"})
    assert body["packages"][0]["metadata"]["license"] == "MIT"
