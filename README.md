# 本地依赖解析 API（Python · FastAPI · packaging）

一个完全本地化的软件依赖解析服务：仓库快照随请求提交，基于
[`packaging`](https://packaging.pypa.io/) 实现 PEP 440（版本/约束）、
PEP 503（包名规范化）与 **PEP 508（环境标记 marker）**，通过带回溯的
搜索生成**确定性锁定清单**；无解时返回从根需求到冲突包的**约束来源链**。
`/upgrade` 在现有锁定清单（`current_lock`）上升级单个目标包：取能完成
整体解析的最高版本，并最小化其余包相对当前锁的变更数量。
`/resolve-matrix` 把**同一份快照与根约束**提交给 **2～8 个带唯一 `id` 的
目标环境**：逐环境复用 `/resolve` 的全部规则求解，返回按 `id` 排序的各环境
锁定清单，以及按包名排序的跨环境版本矩阵（每个包记录各环境版本——未出现为
`null`——并标记 `shared` / `divergent`），用于快速定位跨平台锁定差异。
`/audit-lock` 对现有锁定清单做**只审计、不重新求解**的自洽性检查：按锁定
版本从根包遍历已激活依赖，报告缺失、版本不可用、约束不满足与多余的包。
`/dependency-paths` 在审计通过的锁定清单上**解释目标包为何出现**：按锁定
版本与目标环境激活的依赖建图，返回从根包到目标包的全部最短包路径
（菱形依赖保留等长路径，依赖环不重复节点、不会无限遍历）；最短路径条数
超过固定预算 **1000** 时返回 **409 / `status:"limit"`**，不构造路径列表。
`/install-plan` 同样在审计通过的锁定清单上**规划并行安装顺序**：只对根
可达包按已激活依赖建图，把**强连通分量压缩为 DAG**，输出**依赖优先的
并行安装批次**——同一批内的包互不依赖可并行安装，循环依赖的包收缩为
一个标记 `cyclic` 的原子 batch item（列出内部包），批次/分量/包名全部
确定性排序，根包所在分量处于最后一批。
`/sbom` 同样**先审计 `current_lock`**，锁有效时沿已激活依赖图导出
**确定性 JSON 物料清单（SBOM）**：每个包给出规范化名称、版本、PURL
（Package URL）、依赖名称及候选版本随快照携带的 `source_url` / `sha256`
/ `license` 元数据；元数据缺失只形成 `warnings`，不阻断导出。
`/license-policy` 也**先审计 `current_lock`**，锁有效时解析各可达包锁定
版本 `metadata.license` 的 **SPDX `AND`/`OR`/括号表达式**，按请求的
`allow` / `deny` 标识集合做**三态判定**（允许 / 拒绝 / 未知），返回按包名
排序的 `violations` 与 `unknowns`，每项附根包到该包的**全部最短路径**；
某命中包的最短路径条数超过固定预算 **1000** 时整体返回
**409 / `status:"limit"`**（按包名顺序命中首个超限项）；
非法 SPDX 表达式或 allow/deny 规则重叠返回 422。
`/lock-diff` 在**同一份仓库快照与同一目标环境**下提交 `before_lock` 与
`after_lock` 两份锁定清单：两份锁**各自独立复用 `/audit-lock` 的同一套
规则**校验，任一无效即整体 **409** 并分别标注 before/after 的审计问题；
均有效时**只比较根可达包**，按规范化包名输出 `added` / `removed` /
`upgraded` / `downgraded`（版本方向按 PEP 440 判断），每个变化项同时
给出其在前后依赖图中的**全部最短根路径**（不存在的一侧为空数组）；
某变化项的最短路径条数超过固定预算 **1000** 时整体返回
**409 / `status:"limit"`**（按既有包名顺序命中首个超限项）。
`/explain-version` 做**反事实版本解释**：沿用 `/resolve` 的仓库、根约束
与目标环境，先按原规则求出**基准锁**（目标包不可达返回 422），再把
`target_package` 强制钉在 `target_version` 上整体重解——可行时返回新锁
及相对基准锁的 `added` / `removed` / `changed`，不可行时返回 **409**
并复用约束来源链说明阻塞原因。
`/lock-groups` 在 `/resolve-matrix` 同样的请求上求解**覆盖全部目标环境
所需数量最少的锁文件集合**：先按环境 `id` 的稳定顺序逐环境复用
`/resolve` 规则各求一份候选锁（任一环境无解整体 **409** 并保留该环境的
冲突来源链），再把**去重后的每份候选锁在所有环境上按 `/audit-lock`
规则交叉校验**，以“覆盖全部环境的锁文件数量最少”为目标做精确集合覆盖
选择；并列最优时按锁内容及环境 id 的稳定序裁决，响应按稳定组 id 排列、
每组给出覆盖环境与锁内容，同一输入结果确定。`/resolve-matrix` 与
`/lock-groups` 还共享一个**请求级求解预算**（环境变量
`MATRIX_ATTEMPT_LIMIT` 配置）：同一次请求内所有环境的候选尝试次数累计
计数，达到上限立即停止后续环境的求解，返回 **409 / `status:"limit"`**
（触发环境、已用次数与上限）；环境按 `id` 稳定顺序执行，输入重排不改变
截断位置与响应。单环境 `/resolve` 不使用该预算，仍沿用固定的每实例
尝试上限。

- **无远程访问**：不访问 PyPI 或任何索引，不做磁盘缓存，全部数据在请求内存中处理。
- **目标环境随请求给定**：每条依赖可携带 PEP 508 marker，由请求必填的
  `target_environment`（`python_version` / `sys_platform` / `platform_machine`）
  决定是否激活；**服务端不读取宿主机的任何平台信息**。
- **仅激活依赖参与求解**：marker 为假的依赖不进入全局约束、回溯、冲突来源链与 `edges`。
- **全局唯一版本**：同一包（PEP 503 规范化后）在整棵依赖树中只能选定一个版本。
- **高版本优先**：候选版本严格按 PEP 440 从高到低尝试，失败即回溯到更低版本。
- **最小变更升级**：`/upgrade` 只考虑严格高于当前版本的目标候选，取能完成
  整体解析的最高版本；该版本下在所有有效解中优先选择非目标包相对
  `current_lock` 新增/删除/版本变化数量最少的解。
- **环安全**：依赖环（含自环、菱形依赖）不会导致重复展开；环上的新约束仍会校验。
- **确定性**：结果只取决于快照内容与目标环境，与包键顺序、候选列表顺序无关。
- **等价键合并**：`Foo_Bar`、`foo.bar`、`foo-bar` 等 PEP 503 规范化后同名的
  快照键合并为同一个包（候选版本取并集），而非后写覆盖先写；同版本依赖/元数据
  不一致时稳定返回 422（详见下文“PEP 503 等价键合并”）。

---

## 一、单命令启动（Docker Compose）

```bash
docker compose up --build
```

服务启动后监听：

| 项目 | 地址 |
| --- | --- |
| API 根地址 | `http://localhost:8000` |
| 解析接口 | `POST http://localhost:8000/resolve` |
| 跨环境矩阵接口 | `POST http://localhost:8000/resolve-matrix` |
| 最少锁组接口 | `POST http://localhost:8000/lock-groups` |
| 升级接口 | `POST http://localhost:8000/upgrade` |
| 审计接口 | `POST http://localhost:8000/audit-lock` |
| 依赖路径接口 | `POST http://localhost:8000/dependency-paths` |
| 安装计划接口 | `POST http://localhost:8000/install-plan` |
| SBOM 导出接口 | `POST http://localhost:8000/sbom` |
| 许可证策略接口 | `POST http://localhost:8000/license-policy` |
| 锁差异比较接口 | `POST http://localhost:8000/lock-diff` |
| 版本解释接口 | `POST http://localhost:8000/explain-version` |
| 健康检查 | `GET  http://localhost:8000/healthz` |
| 交互文档（Swagger） | `http://localhost:8000/docs` |
| OpenAPI Schema | `http://localhost:8000/openapi.json` |

端口在 `docker-compose.yml` 的 `ports: ["8000:8000"]` 中调整。

如需调整 `/resolve-matrix` 与 `/lock-groups` 的请求级共享求解预算，在
`docker-compose.yml` 的服务下注入环境变量即可（非法值会让容器在启动时
失败并不断重启，日志可见配置错误）：

```yaml
services:
  dependency-resolver:
    build: .
    environment:
      MATRIX_ATTEMPT_LIMIT: "200000"
    # ...其余原有配置不变
```

本地直接运行时同理：

```bash
MATRIX_ATTEMPT_LIMIT=200000 .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 不使用 Docker 的本地运行方式

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## 二、请求

### `POST /resolve`

请求体字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `repository` | `object` | 是 | 仓库快照：`{包名: [候选版本...]}`；包名按 PEP 503 规范化匹配（大小写/`_`/`.`/`-` 等价）；多个规范化后同名的键（如 `Foo_Bar`、`foo.bar`）其候选版本合并参与求解，规则见下文“PEP 503 等价键合并” |
| `repository.<pkg>[].version` | `string` | 是 | PEP 440 版本号，如 `1.2.3`、`2.0rc1` |
| `repository.<pkg>[].dependencies` | `array` | 否 | 该版本声明的依赖：`{"name", "specifier", "marker"}` |
| `repository.<pkg>[].metadata` | `object` | 否 | 该版本的可选 SBOM 元数据（仅 `/sbom` 使用）：`{"source_url", "sha256", "license"}`，三项均可缺省 |
| `…metadata[].source_url` | `string` | 否 | 该版本源码/分发包的绝对 URL（仅接受 `http`/`https`）；空串/缺省视为未提供 |
| `…metadata[].sha256` | `string` | 否 | 该版本分发包的 SHA-256 摘要（64 位十六进制字符，大小写接受、输出统一小写）；空串/缺省视为未提供 |
| `…metadata[].license` | `string` | 否 | 许可证标识（SPDX）或许可证文本；空串/缺省视为未提供 |
| `…dependencies[].name` | `string` | 是 | 被依赖包名（PEP 503 规范化匹配） |
| `…dependencies[].specifier` | `string` | 否 | PEP 440 版本约束，如 `>=1.0,<2.0`；空串表示不约束 |
| `…dependencies[].marker` | `string` | 否 | PEP 508 环境标记表达式（**不含**前导分号），如 `"sys_platform == 'linux'"`；空串表示无条件激活 |
| `root` | `string` | 是 | 根包名，必须存在于 `repository` |
| `target_environment` | `object` | 是 | marker 求值所用的目标环境，**三项全部必填**，值完全取自请求 |
| `target_environment.python_version` | `string` | 是 | 目标 Python 版本（PEP 440），如 `3.11`、`3.12.4` |
| `target_environment.sys_platform` | `string` | 是 | 目标操作系统（对应 `sys.platform`），如 `linux`、`win32`、`darwin` |
| `target_environment.platform_machine` | `string` | 是 | 目标 CPU 架构（对应 `platform.machine()`），如 `x86_64`、`aarch64`、`AMD64` |
| `specifier` | `string` | 否 | 对根包的 PEP 440 约束，如 `>=1.0,<2.0`；空串表示取最高版本 |
| `allow_prereleases` | `boolean` | 否 | 是否允许预发布（`a/b/rc/dev`），默认 `false`（pip 跟随语义：约束显式钉住预发布时仍可用） |

### PEP 508 marker 规则

- 每条依赖可选一个 `marker` 表达式，支持 `and` / `or` / 括号与比较
  （`==`、`!=`、`>=`、`>`、`<`、`<=`、`~=`、`in`、`not in`），例如：

  ```json
  {"name": "pywin32", "specifier": ">=300", "marker": "sys_platform == 'win32'"}
  ```

  ```json
  {"name": "arm-accel", "marker": "platform_machine == 'aarch64' and python_version >= '3.10'"}
  ```

- marker **只允许引用三个变量**：`python_version`、`sys_platform`、
  `platform_machine`。引用任何其它名称（`os_name`、`platform_system`、
  `python_full_version`、`implementation_name`、`extra` 等）都属于越界，
  返回 **422**；marker 语法非法同样返回 **422**。错误信息会定位到
  **包、版本与依赖**，形如：

  ```text
  包 'app==1.2.3' 对 'some-dep' 的依赖 的 marker 'python_version >>> 3.9' 不是合法的 PEP 508 标记: ...
  包 'app==1.0' 对 'x' 的依赖 的 marker 'os_name == "posix"' 引用了不允许的变量 'os_name'；仅允许引用：platform_machine、python_version、sys_platform
  ```

- 环境值**完全取自请求**：服务进程不会调用 `sys` / `platform` 探测宿主机，
  因此在 Linux 容器里提交 `sys_platform: "win32"` 的请求，会严格按
  Windows 环境求解。
- **只有求值为真的依赖激活**：未激活依赖不会进入全局约束、回溯搜索、
  冲突来源链（409 的 `constraints.chain`）与输出的 `edges`；即使它引用了
  不存在的包或无解版本，也完全不影响结果。
- marker 在解析前对快照一次性求值，同一输入（含 `target_environment`）
  的输出逐字节一致。
- 注意：marker 无论激活与否都会做语法与变量范围校验——非法 marker
  即使在该环境下不会生效，也仍然返回 422。

### PEP 503 等价键合并

快照的包名键按 PEP 503 规范化（小写，`.` / `_` / 连续 `-` 折叠为单个
`-`），因此 `Foo_Bar`、`foo.bar`、`foo-bar`、`foo---bar` 都是**同一个
包** `foo-bar`。当快照中同时出现多个规范化后同名的键时：

- **候选版本合并**：所有等价键下的候选并入同一个版本集合，按 PEP 440
  降序排列，被全部端点（`/resolve`、`/resolve-matrix`、`/lock-groups`、
  `/upgrade`、`/audit-lock`、`/dependency-paths`、`/install-plan`、
  `/sbom`、`/license-policy`、`/lock-diff`、`/explain-version`）一致
  使用——后写的键**不会覆盖**先写的键；低版本键独有的版本、依赖与元数据
  都不会丢失。
- **同一规范化版本去重规则**：同一版本（PEP 440 等价，如 `1.0` 与
  `1.0.0`）在多个键（或同一键内）重复出现时，按目标环境过滤 marker
  **激活后的依赖声明**与 `metadata`（`source_url` / `sha256` /
  `license`）比较：完全一致则去重为一条候选；**不一致则返回 422
  `invalid_snapshot`**，报错列出涉及的全部等价键。
- **与 JSON 键顺序无关**：等价键按规范化名与原始键文本稳定遍历，合并、
  去重与 422 报错内容都只取决于快照内容，调换键在 JSON 中的先后位置得到
  逐字节一致的结果或错误。

```json
{
  "repository": {
    "Foo_Bar": [{"version": "2.0"}, {"version": "1.0", "dependencies": [{"name": "z"}]}],
    "foo.bar": [{"version": "3.0"}, {"version": "1.5"}]
  }
}
```

上例 `foo-bar` 的可用版本为合并后的 `3.0 / 2.0 / 1.5 / 1.0`（降序），
`1.0` 上声明的依赖 `z` 仍然参与求解。若再向 `foo-bar` 键加入
`{"version": "2.0", "dependencies": [...]}` 但其依赖或元数据与
`Foo_Bar` 下的 `2.0` 不一致，则整份快照返回 422。

### 成功请求示例（含回溯）

```bash
curl -s -X POST http://localhost:8000/resolve \
  -H 'Content-Type: application/json' \
  -d @examples/resolve.json
```

`web-framework 3.1.0` 要求 `shared-util==2.0.0`，而 `auth-lib` 要求
`<2.0`，求解器回溯改选 `web-framework 2.4.0`：

```json
{
  "status": "ok",
  "root": "app",
  "root_version": "1.0.0",
  "locked": {
    "app": "1.0.0",
    "auth-lib": "0.9.0",
    "shared-util": "1.5.0",
    "web-framework": "2.4.0"
  },
  "edges": [
    {"from": "root", "to": "app", "specifier": "*"},
    {"from": "app==1.0.0", "to": "auth-lib", "specifier": "*"},
    {"from": "app==1.0.0", "to": "web-framework", "specifier": ">=2.0"},
    {"from": "auth-lib==0.9.0", "to": "shared-util", "specifier": "<2.0"},
    {"from": "web-framework==2.4.0", "to": "shared-util", "specifier": ">=1.0,<2.0"}
  ]
}
```

- `locked`：按规范化包名排序的**锁定清单**（包 → 全局唯一版本）。
- `edges`：按声明方/被依赖方排序的**依赖边**；空约束统一显示为 `*`，
  第一条恒为 `root → 根包`。

### 跨环境示例（同一快照，不同 `target_environment`）

同一份仓库快照中的 `app 2.0.0` 声明了按平台 / 架构 / Python 版本激活的
marker 依赖（`linux-helper`、`win-helper`、`speedlib`、`modern-core`、
`legacy-core`）。只改 `target_environment`，锁定结果随之不同：

```bash
# 目标：Linux x86_64 / Python 3.11
curl -s -X POST http://localhost:8000/resolve \
  -H 'Content-Type: application/json' \
  -d @examples/markers-linux.json

# 目标：Windows AMD64 / Python 3.9（同一快照，仅环境不同）
curl -s -X POST http://localhost:8000/resolve \
  -H 'Content-Type: application/json' \
  -d @examples/markers-windows.json
```

Linux 环境（`linux-helper` 拉入 `native-bindings==2`，激活 `speedlib`
与 `modern-core`；`win-helper`、`legacy-core` 未激活，不出现在结果中）：

```json
{
  "status": "ok",
  "root": "app",
  "root_version": "2.0.0",
  "locked": {
    "app": "2.0.0",
    "linux-helper": "1.2.0",
    "modern-core": "4.0.0",
    "native-bindings": "2",
    "speedlib": "1.0.0"
  },
  "edges": [
    {"from": "root", "to": "app", "specifier": "*"},
    {"from": "app==2.0.0", "to": "linux-helper", "specifier": ">=1.0"},
    {"from": "app==2.0.0", "to": "modern-core", "specifier": "*"},
    {"from": "app==2.0.0", "to": "speedlib", "specifier": "*"},
    {"from": "linux-helper==1.2.0", "to": "native-bindings", "specifier": "==2"}
  ]
}
```

Windows 环境（`win-helper` 拉入 `native-bindings==1`，激活
`legacy-core`；`speedlib` 要求 `x86_64` 而未激活）：

```json
{
  "status": "ok",
  "root": "app",
  "root_version": "2.0.0",
  "locked": {
    "app": "2.0.0",
    "legacy-core": "0.9.0",
    "native-bindings": "1",
    "win-helper": "1.2.0"
  },
  "edges": [
    {"from": "root", "to": "app", "specifier": "*"},
    {"from": "app==2.0.0", "to": "legacy-core", "specifier": "*"},
    {"from": "app==2.0.0", "to": "win-helper", "specifier": ">=1.0"},
    {"from": "win-helper==1.2.0", "to": "native-bindings", "specifier": "==1"}
  ]
}
```

即使请求运行在 Linux 容器中，第二次请求仍严格按 `win32` / `AMD64` /
`3.9` 求解——环境值不会回退到宿主机。

### 无解请求示例（返回约束来源链）

```bash
curl -s -X POST http://localhost:8000/resolve \
  -H 'Content-Type: application/json' \
  -d @examples/conflict.json
```

`left` 与 `right` 对 `core` 给出互斥钉死约束，返回 `409`：

```json
{
  "status": "conflict",
  "message": "依赖约束无解，冲突包：core",
  "conflicts": [
    {
      "subject": "core",
      "kind": "incompatible",
      "message": "已选 core==1.0 与约束交集 ==1.0,==2.0 不兼容",
      "constraints": [
        {"chain": [
          {"package": null, "version": null, "requires": "*"},
          {"package": "app", "version": "1.0.0", "requires": "*"},
          {"package": "left", "version": "1.0", "requires": "==1.0"}
        ]},
        {"chain": [
          {"package": null, "version": null, "requires": "*"},
          {"package": "app", "version": "1.0.0", "requires": "*"},
          {"package": "right", "version": "1.0", "requires": "==2.0"}
        ]}
      ],
      "partial_selection": {"app": "1.0.0", "core": "1.0", "left": "1.0", "right": "1.0"}
    }
  ]
}
```

每条 `chain` 都是一跳约束来源：`package=null` 表示请求本身（根需求），
其后每一跳表示“`<package>==<version>` 声明了 `requires`”。同一冲突包上
所有互斥约束的来源链都会列出（回溯中尝试过的候选版本同样会出现）。

`kind` 取值：

- `no_candidates`：约束交集下没有任何候选版本（或该包不在快照中）；
- `incompatible`：包已选定版本后，环/菱形路径带来了不兼容约束。

### 其他状态码

| 状态码 | 含义 |
| --- | --- |
| `200` | 解析成功 |
| `409` | 约束无解（`status: "conflict"`）；或搜索超过内置尝试上限（`status: "limit"`） |
| `422` | 请求/快照非法：非 PEP 440 版本、非法约束串、**marker 语法非法或引用越界变量**、`target_environment` 缺失/字段非法、根包不在快照中、字段校验失败等 |

`GET /healthz` 返回 `{"status":"ok"}`。

### `POST /resolve-matrix`

同一份仓库快照与根约束，一次提交给 **2～8 个目标环境**分别求解，直接得到
跨平台锁定差异。请求体沿用 `/resolve` 的 `repository` / `root` /
`specifier` / `allow_prereleases`（语义完全一致），只把单个
`target_environment` 换成带唯一 `id` 的 `target_environments` 列表：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target_environments` | `array` | 是 | **2～8 个**目标环境；少于 2 个或多于 8 个返回 422 |
| `target_environments[].id` | `string` | 是 | 环境标识（PEP 503 包名字符集：字母数字与 `._-`，首尾为字母/数字）；同一次请求内**必须唯一**，重复返回 422 |
| `target_environments[].python_version` | `string` | 是 | 同 `/resolve` 的 `target_environment.python_version` |
| `target_environments[].sys_platform` | `string` | 是 | 同上 |
| `target_environments[].platform_machine` | `string` | 是 | 同上 |

每个环境**独立复用 `/resolve` 的全部求解规则**（marker 激活、MRV/回溯、
预发布跟随语义、每环境尝试上限），互不影响；但各环境的候选尝试次数
**累计计入同一次请求的共享求解预算**（见下文“请求级求解预算”）。环境
**按 `id` 升序的稳定顺序**逐个求解，快照与根约束只校验一次。

```bash
curl -s -X POST http://localhost:8000/resolve-matrix \
  -H 'Content-Type: application/json' \
  -d @examples/resolve-matrix.json
```

示例把前述跨平台快照提交给三个环境（Linux x86_64 / Windows AMD64 /
Linux aarch64）。**全部环境有解时返回 200**：`results` 是各环境的
`root_version` 与 `locked`，**按 `id` 排序**；`matrix` 是跨环境版本矩阵，
**按包名排序**——每行给出该包在每个环境的版本（未出现在该环境锁定清单中
为 `null`），并标记：

- `"shared"`：每个环境都锁定了该包且版本完全相同；
- `"divergent"`：版本不同，或该包只出现在部分环境（对应 `versions` 中的 `null`）。

```json
{
  "status": "ok",
  "root": "app",
  "results": [
    {
      "id": "linux-arm64-py311",
      "root_version": "2.0.0",
      "locked": {
        "app": "2.0.0",
        "linux-helper": "1.2.0",
        "modern-core": "4.0.0",
        "native-bindings": "2"
      }
    },
    {
      "id": "linux-x64-py311",
      "root_version": "2.0.0",
      "locked": {
        "app": "2.0.0",
        "linux-helper": "1.2.0",
        "modern-core": "4.0.0",
        "native-bindings": "2",
        "speedlib": "1.0.0"
      }
    },
    {
      "id": "win-amd64-py39",
      "root_version": "2.0.0",
      "locked": {
        "app": "2.0.0",
        "legacy-core": "0.9.0",
        "native-bindings": "1",
        "win-helper": "1.2.0"
      }
    }
  ],
  "matrix": [
    {
      "name": "app",
      "versions": {"linux-arm64-py311": "2.0.0", "linux-x64-py311": "2.0.0", "win-amd64-py39": "2.0.0"},
      "state": "shared"
    },
    {
      "name": "native-bindings",
      "versions": {"linux-arm64-py311": "2", "linux-x64-py311": "2", "win-amd64-py39": "1"},
      "state": "divergent"
    },
    {
      "name": "speedlib",
      "versions": {"linux-arm64-py311": null, "linux-x64-py311": "1.0.0", "win-amd64-py39": null},
      "state": "divergent"
    }
  ]
}
```

（为节省篇幅，上例 `matrix` 只展开了三行；实际响应包含全部出现在任一环境
锁定清单中的包。）由矩阵可直接读出：根包三环境一致（`shared`）；
`native-bindings` 在 Windows 被锁到 `1`、Linux 锁到 `2`（版本差异型
`divergent`）；`speedlib` 只在 x86_64 激活（缺失型 `divergent`，缺失列为
`null`）。根包本身也是矩阵的一行：环境相关的回溯可能让某些环境改选更低的
根版本，此时该根包行同样为 `divergent`，各环境实际锁定的根版本以
`results[].root_version` 为准。

**任一环境无解时整体返回 409**（即使其他环境有解），服务端仍会跑完全部
环境，`failures` 按 `id` 排序列出**各失败环境的原冲突结果**——内容与对该
环境单独调用 `/resolve` 得到的 409 完全一致（`status` / `message` /
`conflicts` 约束来源链）：

```bash
curl -s -X POST http://localhost:8000/resolve-matrix \
  -H 'Content-Type: application/json' \
  -d @examples/resolve-matrix-conflict.json
```

```json
{
  "status": "conflict",
  "message": "1 个目标环境无解（共 2 个）：win-amd64",
  "failures": [
    {
      "id": "win-amd64",
      "status": "conflict",
      "message": "依赖约束无解，冲突包：core",
      "conflicts": [
        {
          "subject": "core",
          "kind": "incompatible",
          "message": "已选 core==1.0 与约束交集 ==1.0,==2.0 不兼容",
          "constraints": [
            {"chain": [
              {"package": null, "version": null, "requires": "*"},
              {"package": "app", "version": "1.0.0", "requires": "*"},
              {"package": "left", "version": "1.0", "requires": "==1.0"}
            ]},
            {"chain": [
              {"package": null, "version": null, "requires": "*"},
              {"package": "app", "version": "1.0.0", "requires": "*"},
              {"package": "right", "version": "1.0", "requires": "==2.0"}
            ]}
          ],
          "partial_selection": {"app": "1.0.0", "core": "1.0", "left": "1.0", "right": "1.0"}
        }
      ]
    }
  ]
}
```

上例中 `left → core==1.0` 无条件激活，而 `right → core==2.0` 只在
`win32` 激活：Linux 环境正常锁定，Windows 环境互斥冲突，因此整体 409 且
`failures` 只含 `win-amd64`（409 响应不返回成功环境的锁定清单）。

`/resolve-matrix` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 全部环境求解成功，返回按 `id` 排序的 `results`（各含 `root_version` 与 `locked`）与按包名排序的 `matrix` |
| `409` | 至少一个环境无解或超过该环境自身的搜索上限：`status: "conflict"`，`failures` 按 `id` 排序列出各失败环境的原冲突结果（单环境的 `status` 也可能为 `"limit"`）；**或同请求累计尝试次数超过请求级共享预算：`status: "limit"`，立即停止后续环境求解**（见下文“请求级求解预算”） |
| `422` | 请求/快照非法（同 `/resolve`），或环境数量不在 2～8、`id` 非法、**`id` 重复** |

#### 请求级求解预算（`/resolve-matrix` 与 `/lock-groups` 共用）

两个多环境接口除每个环境**自身**固定的尝试上限（100,000 次，与
`/resolve` 完全相同）外，还受一个**请求级共享预算**约束：同一次请求内
各环境的候选尝试次数**累计计数**，环境按 **`id` 升序的稳定顺序**执行，
一旦累计值达到预算上限，**正在求解的环境立即中止，且其后的环境不再启动**
（整体直接 409，不再像普通冲突那样跑完全部环境）。这样即便单个环境都未
超过自身上限，整个请求的搜索量也有一个确定的总闸门；同时由于执行顺序只
取决于环境 `id`，**重排请求中环境的提交位置不会改变截断发生的环境与
409 响应**。

预算上限通过环境变量配置（服务启动时读取）：

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `MATRIX_ATTEMPT_LIMIT` | `800000`（= 8 个环境各自的 100,000 上限之和） | 一次 `/resolve-matrix` 或 `/lock-groups` 请求内，所有环境候选尝试次数的累计上限；必须是不小于 1 的十进制正整数。未设置时取默认值；**设置为空、`0`、负数或非整数等非法值会导致服务启动失败**（容器不断重启并在日志中打印配置错误），而不是拖到首个请求才报错 |

默认值取“8 个环境各用满自身上限”之和，因此**默认配置下两个接口的行为
与引入预算前完全一致**——任何环境都会先撞上自身的 100,000 上限（按
`failures[].status="limit"` 的原冲突结果报告、继续跑完全部环境）；只有
显式把 `MATRIX_ATTEMPT_LIMIT` 调小，请求级截断才可能先发生。

预算耗尽时的 409 与“某环境无解”的 409 形态不同，负载如下：

```json
{
  "status": "limit",
  "message": "请求级共享求解预算在环境 'linux-x64' 的求解中耗尽：各目标环境累计已尝试 5 个候选版本，达到上限 5；后续环境已停止求解",
  "environment": "linux-x64",
  "used": 5,
  "limit": 5
}
```

| 字段 | 说明 |
| --- | --- |
| `status` | 固定 `"limit"` |
| `environment` | 触发预算耗尽的环境 `id`；环境按 `id` 稳定顺序执行，该值与后续环境集合只取决于环境集合本身，与请求中的提交顺序无关 |
| `used` | 停止时同请求内各环境累计已尝试的候选版本次数（恰等于 `limit`） |
| `limit` | 本次请求生效的共享预算上限（即启动时的 `MATRIX_ATTEMPT_LIMIT`） |

注意区分两种 `"limit"`：环境**自身**尝试超限仍出现在
`failures[].status="limit"` 中（带该环境的冲突点，服务端继续跑完其余
环境，保留各接口原有冲突来源链）；只有请求级共享预算耗尽才返回顶层
`status:"limit"`（不带 `failures`，后续环境不求解）。单环境 `/resolve`
不读取 `MATRIX_ATTEMPT_LIMIT`，上限语义保持不变。

### `POST /lock-groups`

在**同一份仓库快照、根约束与 2～8 个带唯一 `id` 的目标环境**上，求解
“**用最少的锁文件覆盖全部环境**”。请求体与 `/resolve-matrix` **完全相同**
（`repository` / `root` / `specifier` / `allow_prereleases` /
`target_environments`，字段与校验语义一致，包括环境数量 2～8 与 `id`
唯一）。

处理流程：

1. **逐环境生成候选锁**：环境按 **`id` 升序的稳定顺序**逐个求解，每个
   环境独立复用 `/resolve` 的全部求解规则（marker 激活、MRV/回溯、预发布
   跟随语义、每环境尝试上限），各得到一份确定性候选锁；各环境的候选尝试
   次数与 `/resolve-matrix` **共用同一个请求级共享预算**
   （`MATRIX_ATTEMPT_LIMIT`，见上文）。**任一环境无解时整体返回 409**：
   服务端仍会跑完全部环境，`failures` 按 `id` 排序列出各失败环境的原冲突
   结果——内容与 `/resolve-matrix` 的 409、以及对该环境单独调用
   `/resolve` 得到的 409 完全一致（`status` / `message` / `conflicts`
   约束来源链），成功环境的锁不随 409 返回；**仅当共享预算耗尽时立即
   停止后续环境求解**，返回顶层 `status:"limit"`（触发环境、`used`、
   `limit`，形态与 `/resolve-matrix` 完全相同）；
2. **候选锁按内容去重**：来自不同环境但锁内容（规范化包名 → 版本）完全
   相同的候选只保留一份——它们本就是同一份锁文件；
3. **跨环境交叉校验**：把去重后的**每一份候选锁**当作 `current_lock`，在
   **每一个环境**上按 `/audit-lock` 的同一套规则审计（marker 按**被审计
   环境**求值）：锁在某环境下无任何审计问题（无 missing / unavailable /
   constraint_mismatch / extraneous）时，才算这份锁**可覆盖**该环境。
   每个环境自己求出的候选锁必然可覆盖自身，因此至少存在一个可行覆盖；
4. **精确选择最少锁组**：在至多 8 份候选锁上枚举全部子集，取并集覆盖
   全部环境且**锁文件数量最少**者（精确的最小集合覆盖，非启发式近似）。
   **并列最优时按锁内容及环境 id 的稳定序裁决**：候选锁先按锁内容的稳定
   键（逐 `(包名, 版本)` 对的字典序）排列，再比较“每个环境 id（升序）由
   内容序最靠前的哪一份可覆盖锁负责”的索引元组，取字典序最小者；
5. 成功响应的锁组**按稳定组 id 排列**，同一输入（含环境提交顺序变化）
   结果逐字节一致。

响应字段：

| 字段 | 说明 |
| --- | --- |
| `status` | 固定 `"ok"` |
| `root` | 规范化（PEP 503）后的根包名 |
| `groups` | 最少锁组列表，**按组 id 稳定排序** |
| `groups[].id` | **由锁内容派生的稳定组 id**：`lg-` + 锁内容（按包名排序的 `包名==版本` 序列）SHA-256 的 12 位十六进制前缀；锁内容相同则 id 相同，与来源环境、请求顺序无关 |
| `groups[].environments` | 该锁通过 `/audit-lock` 交叉审计、**可覆盖的全部环境 id**，按 id 排序；各组覆盖集的并集即全部目标环境（不同锁组的覆盖集在罕见情况下可能交叠，各自如实列出） |
| `groups[].locked` | 锁内容：规范化包名 → PEP 440 版本，按包名排序（即对应环境按 `/resolve` 规则求出的候选锁） |

```bash
curl -s -X POST http://localhost:8000/lock-groups \
  -H 'Content-Type: application/json' \
  -d @examples/lock-groups.json
```

示例中 `app 2.0.0` 无条件拉入 `std-kit`，非 Linux 平台激活
`posix-plugin`，Linux 平台激活 `unix-plugin>=2.0`。三个环境的候选锁里，
**Windows 与 macOS 求出的锁内容完全相同**（去重为一份），交叉审计下该锁
同时覆盖两个环境；Linux 锁只覆盖 Linux。覆盖全部环境的最少锁文件数量为
**2**：

```json
{
  "status": "ok",
  "root": "app",
  "groups": [
    {
      "id": "lg-ac4b0341e3f5",
      "environments": ["mac-arm64", "win-amd64"],
      "locked": {
        "app": "2.0.0",
        "posix-plugin": "1.0.0",
        "std-kit": "1.0.0"
      }
    },
    {
      "id": "lg-c8a263a3964d",
      "environments": ["linux-x64"],
      "locked": {
        "app": "2.0.0",
        "std-kit": "1.0.0",
        "unix-plugin": "2.1.0"
      }
    }
  ]
}
```

交叉校验完全复用 `/audit-lock` 的判定：例如某环境因 marker 激活了额外
依赖，那么缺该包的外来锁会在该环境报 `missing`、不可覆盖；外来锁多出该
环境不可达的包则报 `extraneous`；版本不满足该环境的传递约束则报
`constraint_mismatch`。因此在全部环境都激活同一组包、但部分环境的约束
更紧时，为最紧环境求出的**较低版本锁**往往能反向通过宽松环境的审计——
此时**一份锁即可覆盖全部环境**（最少锁组数为 1）。

任一环境无解时返回 **409**，形态与 `/resolve-matrix` 的 409 完全一致：

```bash
curl -s -X POST http://localhost:8000/lock-groups \
  -H 'Content-Type: application/json' \
  -d @examples/lock-groups-conflict.json
```

```json
{
  "status": "conflict",
  "message": "1 个目标环境无解（共 2 个）：win-amd64",
  "failures": [
    {
      "id": "win-amd64",
      "status": "conflict",
      "message": "依赖约束无解，冲突包：core",
      "conflicts": [
        {
          "subject": "core",
          "kind": "incompatible",
          "message": "已选 core==1.0 与约束交集 ==1.0,==2.0 不兼容",
          "constraints": [
            {"chain": [
              {"package": null, "version": null, "requires": "*"},
              {"package": "app", "version": "1.0.0", "requires": "*"},
              {"package": "left", "version": "1.0", "requires": "==1.0"}
            ]},
            {"chain": [
              {"package": null, "version": null, "requires": "*"},
              {"package": "app", "version": "1.0.0", "requires": "*"},
              {"package": "right", "version": "1.0", "requires": "==2.0"}
            ]}
          ],
          "partial_selection": {"app": "1.0.0", "core": "1.0", "left": "1.0", "right": "1.0"}
        }
      ]
    }
  ]
}
```

`/lock-groups` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 全部环境求解成功且完成交叉校验，返回覆盖全部环境的最少锁组（按稳定组 id 排序） |
| `409` | 至少一个环境无解或超过该环境自身的搜索上限：`status: "conflict"`，`failures` 按 `id` 排序列出各失败环境与 `/resolve` 同形的原冲突结果（保留冲突来源链；单环境的 `status` 也可能为 `"limit"`）；**或同请求累计尝试次数超过请求级共享预算：`status: "limit"`，立即停止后续环境求解**（与 `/resolve-matrix` 同形） |
| `422` | 请求/快照非法（同 `/resolve`），或环境数量不在 2～8、`id` 非法、**`id` 重复** |

### `POST /upgrade`

在现有锁定清单上升级**单个目标包**。请求体包含 `/resolve` 的全部字段
（`repository` / `root` / `target_environment` / `specifier` /
`allow_prereleases`，语义完全一致），并附加两个字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `current_lock` | `object` | 是 | 当前锁定清单：`{包名: 版本}`；包名按 PEP 503 规范化匹配，版本须为合法 PEP 440。仅作为最小化变更的参照，不参与约束求解 |
| `target` | `string` | 是 | 要升级的包名；**必须存在于 `current_lock` 中**，否则返回 422 |

升级规则：

1. 只考虑 `target` **严格高于** `current_lock[target]` 的候选版本
   （预发布版本遵循 `allow_prereleases`，与 `/resolve` 相同；此外
   `target` 与 `root` 规范化后同名时，用户提交的根 `specifier` 按
   PEP 440 跟随语义放行其显式提到的预发布版本——如 `==2.0rc1` 或
   `>=2.0a1`——升级器内部为逐候选求解生成的 `==候选版本` 钉选不参与
   该判定，普通未约束请求仍排除预发布）；
2. 从高到低尝试候选：以根级 `==版本` 约束钉住目标包后做整体解析，
   **第一个存在可行解的候选即为目标版本**；所有更高候选均无解
   （或根本没有更高版本）时返回 **409**；
3. 目标版本确定后，在该版本的**所有有效解**中，优先选择非目标包相对
   `current_lock` 的**新增 + 删除 + 版本变化数量最少**的解；数量相同时
   沿用 `/resolve` 的确定性版本顺序（高版本优先）；
4. `current_lock` 不约束求解：未出现在新锁定清单中的包记为删除，
   新引入的包记为新增，版本按 PEP 440 比较（`1.0` 与 `1.0.0` 相等，
   不产生变更项）。

```bash
curl -s -X POST http://localhost:8000/upgrade \
  -H 'Content-Type: application/json' \
  -d @examples/upgrade.json
```

示例中 `web-framework` 当前锁定 `2.4.0`：候选 `3.1.0` 要求
`shared-util==2.0.0`，与 `auth-lib` 的 `<2.0` 冲突而被跳过；`3.2.0`
是可行的最高目标版本，且 `shared-util` 保持 `current_lock` 中的
`1.5.0`（变更数最少）：

```json
{
  "status": "ok",
  "root": "app",
  "root_version": "1.0.0",
  "locked": {
    "app": "1.0.0",
    "auth-lib": "0.9.0",
    "shared-util": "1.5.0",
    "web-framework": "3.2.0"
  },
  "changes": [
    {"name": "web-framework", "from": "2.4.0", "to": "3.2.0"}
  ]
}
```

- `locked`：升级后的**完整**锁定清单（按规范化包名排序）。
- `changes`：相对 `current_lock` 的全部变化（含目标包），**按包名排序**；
  `from` 为 `null` 表示新增包，`to` 为 `null` 表示被删除的包。

`/upgrade` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 升级成功，返回完整 `locked` 与 `changes` |
| `409` | 无可行升级（没有严格更高的候选，或所有更高候选都无法完成整体解析，`status: "conflict"` 并附冲突来源链）；或搜索超过内置尝试上限（`status: "limit"`） |
| `422` | 请求/快照非法（同 `/resolve`），或 `target` 不存在于 `current_lock` 中、`current_lock` 含非法 PEP 440 版本 |

### `POST /audit-lock`

对一份**现有锁定清单**做自洽性审计。请求体包含 `/resolve` 的全部字段
（`repository` / `root` / `target_environment` / `specifier` /
`allow_prereleases`，语义完全一致），并附加 `current_lock`（与 `/upgrade`
同名同格式）：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `current_lock` | `object` | 是 | 被审计的锁定清单：`{包名: 版本}`；包名按 PEP 503 规范化匹配，版本须为合法 PEP 440 |

**审计不重新求解、不选择任何版本**——版本完全由 `current_lock` 给定：

1. 从根包的锁定版本出发，按目标环境展开该版本声明的**已激活**依赖
   （marker 语义与 `/resolve` 完全一致：未激活的依赖不参与审计）；
2. 依赖环 / 菱形中同一个包**只展开一次**，但指向它的**每一条入边约束
   都累计核对**（环上回边的约束同样参与）；
3. 包名按 PEP 503 规范化匹配（`Some_Pkg` ≡ `some-pkg`），版本按 PEP 440
   等价性判断（锁中的 `1.0` 与快照中的 `1.0.0` 视为同一版本，`==1.0`
   同样满足）；约束满足判断与求解器共用同一套 pip 预发布跟随语义。

每个有问题的包产出一条 `issue`，类型固定为以下四种：

| `type` | 含义 |
| --- | --- |
| `missing` | 该包按锁定版本的依赖图**可达**，却未出现在 `current_lock` 中（`locked_version` 为 `null`） |
| `unavailable` | 锁定版本**不在仓库快照**中（或包完全不在快照中，`available` 为空） |
| `constraint_mismatch` | 锁定版本**不满足根约束或任一入边依赖约束**；`constraints` 只列未满足的约束，逐条带 `"satisfies": false` |
| `extraneous` | 锁中存在但从根包按锁定版本**不可达**的包（含仅被未激活 marker 依赖要求的包）；`constraints` 恒为空 |

每条 `issue` 包含：

| 字段 | 说明 |
| --- | --- |
| `type` | 上述四种类型之一 |
| `name` | 规范化包名（PEP 503） |
| `locked_version` | 锁中版本；`missing` 时为 `null` |
| `available` | 快照中该包的全部可用版本（PEP 440 降序）；包不在快照中时为 `[]` |
| `constraints` | 累计到该包的入边约束（含根约束，已去重并按来源排序）：每条含 `from`（`root` 或 `pkg==version`）、`specifier`（空约束显示 `*`）；仅 `constraint_mismatch` 的条目额外带 `satisfies`（恒为 `false`） |

无任何问题时返回 `"valid": true` 且 `issues` 为空。`issues` **确定性排序**：
先按类型（`missing` → `unavailable` → `constraint_mismatch` →
`extraneous`），同类型内按规范化包名；与包键 / 候选列表的输入顺序无关。

```bash
curl -s -X POST http://localhost:8000/audit-lock \
  -H 'Content-Type: application/json' \
  -d @examples/audit-lock.json
```

示例快照里：`monitoring-lib` 被依赖却未锁定（missing）、`web-framework`
锁了快照中不存在的 `3.3.0`（unavailable）、`cache-lib` 锁 `1.5.0` 不满足
`>=2.0`（constraint_mismatch）、`stale-pkg` 完全不可达（extraneous），
而 `win-only` 仅在 `sys_platform == 'win32'` 激活、linux 请求下不可达
（extraneous）：

```json
{
  "status": "ok",
  "valid": false,
  "issues": [
    {
      "type": "missing",
      "name": "monitoring-lib",
      "locked_version": null,
      "available": ["1.0.0"],
      "constraints": [
        {"from": "app==1.0.0", "specifier": ">=1.0"}
      ]
    },
    {
      "type": "unavailable",
      "name": "web-framework",
      "locked_version": "3.3.0",
      "available": ["3.2.0", "2.4.0"],
      "constraints": [
        {"from": "app==1.0.0", "specifier": ">=2.0"}
      ]
    },
    {
      "type": "constraint_mismatch",
      "name": "cache-lib",
      "locked_version": "1.5.0",
      "available": ["2.0.0", "1.5.0"],
      "constraints": [
        {"from": "app==1.0.0", "specifier": ">=2.0", "satisfies": false}
      ]
    },
    {
      "type": "extraneous",
      "name": "stale-pkg",
      "locked_version": "0.1.0",
      "available": [],
      "constraints": []
    },
    {
      "type": "extraneous",
      "name": "win-only",
      "locked_version": "1.0",
      "available": ["1.0"],
      "constraints": []
    }
  ]
}
```

遍历细节：

- `missing` / `unavailable` 是**遍历断点**——锁中没有该包、或锁定版本不在
  快照时，无法得知它的依赖声明，因此不沿其继续展开；只经这些断点才可到达
  的锁中包会报 `extraneous`。
- `constraint_mismatch` **不阻断遍历**：锁定版本仍在快照中，其声明的依赖
  照常展开（一份锁可以同时有约束不满足和下游缺包）。
- marker 无论激活与否都做语法与变量范围校验，非法 marker 仍返回 **422**
  （与 `/resolve` 一致）；只有求值为真的依赖进入遍历。

`/audit-lock` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 审计完成（`valid` 为 `true` 或 `false` 都是 200；审计不产生 409） |
| `422` | 请求/快照非法（同 `/resolve`），或 `current_lock` 含非法 PEP 440 版本、同一规范化包名对应多个不同版本 |

### `POST /dependency-paths`

解释**目标包为何出现在锁定清单中**。请求体沿用 `/audit-lock` 的全部字段
（`/resolve` 字段 + `current_lock`），并附加一个 `target`：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `current_lock` | `object` | 是 | 被解释的锁定清单：`{包名: 版本}`，格式同 `/audit-lock` |
| `target` | `string` | 是 | 要解释的目标包名（PEP 503 规范化匹配）；目标为根包时返回单节点路径，不在锁中/不可达时返回 `reachable: false` |

处理流程：

1. **先按 `/audit-lock` 的同一套规则校验 `current_lock`**（含目标环境的
   marker 激活语义）。锁无效时返回 **409**，携带与 `/audit-lock` 逐字节
   一致、确定性排序的 `issues`，**不执行任何路径查询**（响应中没有
   `paths` / `reachable` 字段）；
2. 锁有效时，**不做任何版本选择**：按每个包的**锁定版本**展开它在目标
   环境下的已激活依赖构成有向图（未激活 marker 依赖不是图的边）；
   同一对包之间的多条依赖声明（不同约束文本）只产生一条边；
3. 从根包做无权 BFS，返回到**规范化目标名**的**所有最短包路径**：
   - **菱形依赖**产生的等长路径全部保留（路径数为各分叉的组合数）；
     更长的路径不返回；
   - **依赖环**（含自环）安全：每个包只展开一次，BFS 只记录最短距离上的
     前驱，路径内不重复节点，也不会无限遍历；
   - **路径条数预算（固定 1000 条）**：分层菱形下最短路径条数随层数
     指数增长，逐一构造会拖垮进程。BFS 建立最短前驱图后**先按层做饱和
     计数**（只累加条数、不构造路径），条数超过 1000 即饱和为 1001 并
     返回 **409 / `status:"limit"`**，**不构造路径列表**；未超限时才
     重建并返回全部最短路径；
   - 目标即根包时返回唯一的单节点路径 `[根包]`；
   - 目标不在锁定清单或从根包不可达时返回 `"reachable": false` 与
     `"paths": []`（在有效锁上，锁中包都从根可达，因此不可达通常意味着
     目标根本不在锁中）。

响应字段：

| 字段 | 说明 |
| --- | --- |
| `status` | 固定 `"ok"` |
| `root` / `target` | 规范化（PEP 503）后的根包名与目标包名 |
| `reachable` | 目标是否可达；`false` 时 `paths` 恒为空 |
| `paths` | 最短包路径列表；每条路径是规范化包名序列（**含根节点与目标节点**，路径内为访问次序、不重排）；全部路径按字典序**确定性排序**，与包键/依赖声明/锁键的输入顺序无关 |

```bash
curl -s -X POST http://localhost:8000/dependency-paths \
  -H 'Content-Type: application/json' \
  -d @examples/dependency-paths.json
```

示例锁中 `shared-util 1.5.0` 同时被 `web-framework 3.2.0`
（`>=1.0,<3.0`）与 `auth-lib 0.9.0`（`<2.0`）要求，构成菱形，两条等长
路径都返回（字典序 `auth-lib` 在 `web-framework` 之前）：

```json
{
  "status": "ok",
  "root": "app",
  "target": "shared-util",
  "reachable": true,
  "paths": [
    ["app", "auth-lib", "shared-util"],
    ["app", "web-framework", "shared-util"]
  ]
}
```

目标不在锁定清单中（或不可达）时：

```json
{
  "status": "ok",
  "root": "app",
  "target": "nope",
  "reachable": false,
  "paths": []
}
```

最短路径条数超过固定预算（1000 条）时返回 **409**，不构造路径列表
（`used` 为饱和计数，恒为 `limit + 1`）：

```json
{
  "status": "limit",
  "message": "根包到目标包 'shared-util' 的最短路径条数超过预算：饱和计数 1001，超过上限 1000；未构造路径列表",
  "target": "shared-util",
  "used": 1001,
  "limit": 1000
}
```

`/dependency-paths` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 锁有效，路径查询完成（`reachable` 为 `true` 或 `false` 都是 200） |
| `409` | 锁定清单未通过审计：`status: "invalid_lock"`，`issues` 与 `/audit-lock` 的输出一致（确定性排序），不执行路径查询；或最短路径条数超过固定预算 1000：`status: "limit"`，含 `target` / `used`（恒为 1001）/ `limit`，未构造路径列表 |
| `422` | 请求/快照非法（同 `/resolve`），或 `current_lock` 含非法 PEP 440 版本、同一规范化包名对应多个不同版本、`target` 名称非法 |

### `POST /install-plan`

在**审计通过的锁定清单**上规划**依赖优先的并行安装批次**。请求体沿用
`/audit-lock` 的全部字段（`/resolve` 字段 + `current_lock`，语义完全
一致），无额外字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `current_lock` | `object` | 是 | 据以规划安装顺序的锁定清单：`{包名: 版本}`，格式同 `/audit-lock` |

处理流程：

1. **先按 `/audit-lock` 的同一套规则校验 `current_lock`**（含目标环境的
   marker 激活语义）。锁无效时返回 **409**，携带与 `/audit-lock`
   逐字节一致、确定性排序的 `issues`，**不生成任何安装批次**
   （响应中没有 `batches` 字段）；
2. 锁有效时**不做任何版本选择**：按每个包的**锁定版本**展开它在目标
   环境下的已激活依赖构成有向图（与 `/dependency-paths`、`/sbom` 同一张
   图；节点集恰为**根可达包**，未激活 marker 依赖不是图的边）；
3. **强连通分量（SCC）压缩为 DAG**：互相可达（含自环）的包属于同一个
   强连通分量——环上的包无法以任何先后顺序安装，因此**同一分量作为一个
   batch item 原子安装**；分量之间的依赖边构成无环图（DAG）；
4. **依赖优先的最长路径并行分层**：无跨分量依赖的分量在批次 0，其余
   分量的批次号为其各依赖分量批次号最大值 + 1。由此**任一依赖所在批次
   严格早于依赖它的包**（不晚于），同一批内的分量互不依赖、可并行安装，
   且批次数最少。根包沿依赖边可到达每个可达包，故**根包所在分量必然
   处于最后一批**。

响应字段：

| 字段 | 说明 |
| --- | --- |
| `status` | 固定 `"ok"` |
| `root` | 规范化（PEP 503）后的根包名 |
| `batches` | 并行安装批次列表，**按安装先后（批次号升序）排列**：先执行批次 0，再执行批次 1，以此类推 |
| `batches[][]` | 每个 item 是一个安装单元：单包为 `{"cyclic": false, "name": <包名>, "packages": null}`；循环强连通分量为 `{"cyclic": true, "name": null, "packages": [包名...]}` |
| `batches[][].cyclic` | `false`=单个包（非循环 SCC）；`true`=循环 SCC，分量内的包互相可达、须作为一个原子项安装 |
| `batches[][].name` | 单包 item 的规范化包名；循环分量为 `null` |
| `batches[][].packages` | 循环分量内部的全部规范化包名，**按包名排序**；单包 item 为 `null` |

确定性排序：批次按批次号；**同一批内**单包按包名、循环分量按其内部包名
排序后的元组做字典序排列。结果与包键 / 候选列表 / 依赖声明 / 锁键的
输入顺序无关。

```bash
curl -s -X POST http://localhost:8000/install-plan \
  -H 'Content-Type: application/json' \
  -d @examples/install-plan.json
```

示例中 `shared-util 1.5.0` 与 `plugin-a 1.0.0` **互相依赖**构成循环
分量（最先安装的原子项）；`auth-lib` 与 `web-framework` 都只依赖该
分量、互不依赖，在第二批**并行**安装；根包 `app` 依赖两者，独占
最后一批：

```json
{
  "status": "ok",
  "root": "app",
  "batches": [
    [
      {"cyclic": true, "name": null, "packages": ["plugin-a", "shared-util"]}
    ],
    [
      {"cyclic": false, "name": "auth-lib", "packages": null},
      {"cyclic": false, "name": "web-framework", "packages": null}
    ],
    [
      {"cyclic": false, "name": "app", "packages": null}
    ]
  ]
}
```

无环时所有循环项退化为单包：纯线性链 `app → liba → libb → libc` 得到
四批 `[[libc], [libb], [liba], [app]]`；无依赖的多个独立包与菱形的
同级依赖同批并行；只有根包一个包时返回仅含一个单包项的批次。
**自环**（某包依赖自身）同样标记为 `cyclic` 的单包分量；根包自身与
下游成环时，根循环分量按最长路径规则仍处于最后一批。

`/install-plan` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 锁有效，安装计划生成完成（存在循环分量仍是 200，循环项以 `cyclic: true` 标注） |
| `409` | 锁定清单未通过审计：`status: "invalid_lock"`，`issues` 与 `/audit-lock` 的输出一致（确定性排序），不生成安装批次 |
| `422` | 请求/快照非法（同 `/resolve`），或 `current_lock` 含非法 PEP 440 版本、同一规范化包名对应多个不同版本 |

### `POST /sbom`

在**审计通过的锁定清单**上导出确定性 JSON 物料清单（SBOM）。请求体沿用
`/audit-lock` 的全部字段（`/resolve` 字段 + `current_lock`，语义完全
一致），无额外字段；候选版本可携带的 `source_url` / `sha256` /
`license` 元数据定义在 `repository` 的候选条目上（见上文 `/resolve`
字段表）。

处理流程：

1. **先按 `/audit-lock` 的同一套规则校验 `current_lock`**（含目标环境的
   marker 激活语义）。锁无效时返回 **409**，携带与 `/audit-lock`
   逐字节一致、确定性排序的 `issues`，**不导出任何清单**（响应中没有
   `packages` / `warnings` 字段）；
2. 锁有效时**不做任何版本选择**：按每个包的**锁定版本**沿目标环境下的
   **已激活依赖图**展开（与 `/dependency-paths` 同一张图；未激活 marker
   依赖既不是图的边，也不是导出的包）；
3. 逐包导出清单条目；**元数据缺失不阻断导出**——只在顶层 `warnings`
   中逐项提示。

响应字段：

| 字段 | 说明 |
| --- | --- |
| `status` | 固定 `"ok"` |
| `root` | 规范化（PEP 503）后的根包名 |
| `packages` | 已激活依赖图中的全部包（**含根包**），**按规范化包名排序** |
| `packages[].name` | PEP 503 规范化包名 |
| `packages[].version` | 锁定版本（PEP 440 字符串） |
| `packages[].purl` | [Package URL](https://github.com/package-url/purl-spec)：`pkg:pypi/<规范化名>@<版本>`；版本按 PURL 规则做确定性最小百分号编码（PEP 440 的 `1.0`、`2.0rc1`、`1!2.0` 等均原样输出） |
| `packages[].dependencies` | 该包锁定版本声明的**已激活**依赖的规范化名称：同一依赖的多条声明去重、按名称排序；未激活 marker 依赖不出现；无依赖时为 `[]` |
| `packages[].metadata` | 候选版本携带的元数据：`source_url` / `sha256` / `license`；快照未提供的字段为 `null`（sha256 输出统一小写） |
| `warnings` | 元数据缺失提示，**按包名排序**；仅列出至少缺一个字段的包。每条为 `{"name", "missing"}`，`missing` 是缺失字段名列表，按固定枚举次序 `license` → `sha256` → `source_url` 排列；元数据完整时 `warnings` 为 `[]` |

```bash
curl -s -X POST http://localhost:8000/sbom \
  -H 'Content-Type: application/json' \
  -d @examples/sbom.json
```

示例中四个包均锁定且元数据完整度不一：`app` / `web-framework` 三项齐全，
`auth-lib` 缺 `sha256`，`shared-util 1.5.0` 缺 `source_url`
（快照中存在但未锁定的 `shared-util 2.0.0` / `web-framework 2.4.0`
的元数据不会出现——元数据取自**锁定版本**的候选）：

```json
{
  "status": "ok",
  "root": "app",
  "packages": [
    {
      "name": "app",
      "version": "1.0.0",
      "purl": "pkg:pypi/app@1.0.0",
      "dependencies": ["auth-lib", "web-framework"],
      "metadata": {
        "source_url": "https://example.invalid/src/app-1.0.0.tar.gz",
        "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "license": "Apache-2.0"
      }
    },
    {
      "name": "auth-lib",
      "version": "0.9.0",
      "purl": "pkg:pypi/auth-lib@0.9.0",
      "dependencies": ["shared-util"],
      "metadata": {
        "source_url": "https://example.invalid/src/auth-lib-0.9.0.tar.gz",
        "sha256": null,
        "license": "MIT"
      }
    },
    {
      "name": "shared-util",
      "version": "1.5.0",
      "purl": "pkg:pypi/shared-util@1.5.0",
      "dependencies": [],
      "metadata": {
        "source_url": null,
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "license": "MIT"
      }
    },
    {
      "name": "web-framework",
      "version": "3.2.0",
      "purl": "pkg:pypi/web-framework@3.2.0",
      "dependencies": ["shared-util"],
      "metadata": {
        "source_url": "https://example.invalid/src/web-framework-3.2.0.tar.gz",
        "sha256": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "license": "BSD-3-Clause"
      }
    }
  ],
  "warnings": [
    {"name": "auth-lib", "missing": ["sha256"]},
    {"name": "shared-util", "missing": ["source_url"]}
  ]
}
```

遍历与确定性细节：

- 元数据**只读取锁定版本的候选**：同一包未被锁定的其他版本携带的元数据
  不会导出，也不会与锁定版本合并。
- 同一包名（PEP 503）同一版本在快照中出现多次时（含分布在多个 PEP 503
  等价键下，如 `Foo_Bar` 与 `foo.bar`），依赖声明（按目标环境过滤 marker
  后）与元数据都必须完全一致，否则返回 422；完全重复则合并为一条候选。
- `dependencies` 与 `packages` 都按规范化名排序，`warnings` 按包名排序；
  重复请求同一快照、锁与环境，输出逐字节一致。
- 未激活 marker 依赖不参与：换一个 `target_environment`，已激活图变化，
  导出的包与依赖名随之变化（在新环境下若锁审计失败则返回 409）。

`/sbom` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 锁有效，SBOM 导出完成（即使存在元数据 `warnings` 仍是 200） |
| `409` | 锁定清单未通过审计：`status: "invalid_lock"`，`issues` 与 `/audit-lock` 的输出一致（确定性排序），不导出清单 |
| `422` | 请求/快照非法（同 `/resolve`），或 `current_lock` 含非法 PEP 440 版本、同一规范化包名对应多个不同版本、候选 `metadata.sha256` 不是 64 位十六进制、`metadata.source_url` 不是 `http`/`https` 绝对 URL |

### `POST /license-policy`

在**审计通过的锁定清单**上按调用方给定的 allow/deny 策略判定每个可达包的
许可证。请求体沿用 `/audit-lock` 的全部字段（`/resolve` 字段 +
`current_lock`，语义完全一致），并附加两个策略字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `allow` | `string[]` | 否 | **允许**的 SPDX 许可证标识集合，缺省为 `[]`；每项必须是**单个标识词**（不接受 `AND`/`OR`/括号表达式），如 `"MIT"`、`"Apache-2.0"`、`"GPL-2.0+"`、`"LicenseRef-Proprietary"`；标识**大小写敏感、按字面匹配** |
| `deny` | `string[]` | 否 | **拒绝**的 SPDX 许可证标识集合，格式同 `allow`，缺省为 `[]`；与 `allow` **不得重叠**（同一标识同时出现属于规则冲突，返回 422） |

处理流程：

1. **先按 `/audit-lock` 的同一套规则校验 `current_lock`**（含目标环境的
   marker 激活语义）。锁无效时返回 **409**，携带与 `/audit-lock`
   逐字节一致、确定性排序的 `issues`，**不解析任何许可证表达式**
   （响应中没有 `violations` / `unknowns` 字段）；
2. 锁有效时**不做任何版本选择**：在与 `/dependency-paths`、`/sbom`
   **同一张已激活依赖图**上（按锁定版本、marker 求值后激活的依赖），
   逐包读取其**锁定版本**候选的 `metadata.license`：
   - 未提供（`null` / 空串）：整包判为**未知**（归入 `unknowns`，
     `license` 输出 `null`），不阻断请求；
   - 提供文本：先按 **SPDX 表达式**解析（`AND` / `OR` / 括号，
     `OR` 优先级最低、`AND` 更高；`AND`/`OR` 大小写不敏感，标识词
     大小写敏感），再按三态规则求值；
   - **`AND`/`OR` 两侧都必须以空白分隔**（SPDX 词法规则）：合法写法为
     `MIT OR (Apache-2.0)`、`(MIT) AND (Apache-2.0)`（空格、制表符等
     任意空白均可，多个空白也合法）；`MIT OR(Apache-2.0)`、
     `(MIT)AND(Apache-2.0)`、`MIT AND(Apache-2.0)` 等任一侧紧贴括号或
     表达式边界悬空（`OR MIT`、`MIT OR`）的写法都在词法/语法阶段被拒绝，
     422 错误信息会给出违规运算符（大小写原样）与位置；标识词内部包含
     `AND`/`OR` 字母片段（如真实标识词 `ANDOR`）仍作为单个原子标识处理，
     不会被拆分；
   - 许可证文本不是合法的 SPDX 表达式（含不支持的 `WITH` 例外表达式、
     运算符两侧缺少空白分隔）时返回 **422**，错误信息定位到包与版本；
3. 每个包的判定结果为**三态**之一：

   | 原子标识 / 表达式 | 结果 |
   | --- | --- |
   | 标识在 `deny` 中 | 拒绝 |
   | 标识仅在 `allow` 中 | 允许 |
   | 标识不在两者中 | 未知 |
   | `A AND B` | **全部允许才允许；任一拒绝即拒绝；其余未知** |
   | `A OR B` | **任一允许即允许；全部拒绝才拒绝；其余未知** |

   例如 `MIT AND GPL-3.0-only`（GPL 在 deny 中）→ 拒绝；
   `MIT OR GPL-3.0-only`（MIT 在 allow 中）→ 允许；
   `MIT AND Custom-Internal`（`Custom-Internal` 两集合都没有）→ 未知；
   `GPL-3.0-only OR Custom-Internal`（一拒绝一未知）→ 未知。

响应字段：

| 字段 | 说明 |
| --- | --- |
| `status` | 固定 `"ok"` |
| `root` | 规范化（PEP 503）后的根包名 |
| `violations` | 判定为**拒绝**的包列表，**按规范化包名排序**；允许的包不出现 |
| `unknowns` | 判定为**未知**的包列表（含未提供许可证的包），**按规范化包名排序** |
| `violations[]` / `unknowns[]` | 每项为 `{"name", "license", "paths"}`：`name` 为规范化包名；`license` 为该包锁定版本的原始 SPDX 表达式文本（未提供时为 `null`）；`paths` 为根包到该包的**全部最短包路径**（与 `/dependency-paths` 同语义：含首尾、菱形等长路径全保留、环安全、字典序确定性排序；根包自身为单节点路径 `[root]`）。命中包按包名顺序逐个查询路径，某条查询的条数超过固定预算 1000 时整体返回 **409 / `status:"limit"`**（命中首个超限项），不构造任何路径列表 |

```bash
curl -s -X POST http://localhost:8000/license-policy \
  -H 'Content-Type: application/json' \
  -d @examples/license-policy.json
```

运算符空白边界是 SPDX 词法硬性要求，下列写法均返回 **422**，消息定位到
包/版本与违规运算符（原样大小写）及其位置，合法的空白分隔形式附后对照：

```text
422  MIT OR(Apache-2.0)     # 运算符 'OR' 缺少右侧空白分隔（位置 4）
422  (MIT)AND(Apache-2.0)   # 运算符 'AND' 缺少左侧、右侧空白分隔（位置 5）
422  MIT AND (MIT OR)       # 运算符 'OR' 右侧紧贴 ')'，缺少空白分隔
 200  MIT OR (Apache-2.0)   # 合法：两侧均有空白
 200  (MIT) AND (Apache-2.0)
```

示例中策略允许 `Apache-2.0` / `BSD-3-Clause` / `MIT`、拒绝
`GPL-3.0-only` / `AGPL-3.0-only`：`copyleft-lib 1.0` 声明 `GPL-3.0-only`
构成违规，且它同时被 `web-framework → shared-util 1.5.0` 与
`auth-lib → shared-util 1.5.0` 两条等长菱形路径引入（两条最短路径都
返回）；`json-tool` 的 `JSON OR MIT` 因含允许的 `MIT` 而整体允许；
`internal-thing` 未声明许可证，归入未知：

```json
{
  "status": "ok",
  "root": "app",
  "violations": [
    {
      "name": "copyleft-lib",
      "license": "GPL-3.0-only",
      "paths": [
        ["app", "auth-lib", "shared-util", "copyleft-lib"],
        ["app", "web-framework", "shared-util", "copyleft-lib"]
      ]
    }
  ],
  "unknowns": [
    {
      "name": "internal-thing",
      "license": null,
      "paths": [
        ["app", "internal-thing"]
      ]
    }
  ]
}
```

确定性与遍历细节：

- 许可证只读取**锁定版本**候选的 `metadata.license`；同一包未被锁定的
  其他版本携带的许可证不参与判定，也不会合并。
- 判定与路径都只覆盖**已激活依赖图**中的包（含根包）：换一个
  `target_environment`，激活图变化，参与判定的包随之变化（在新环境下
  若锁审计失败则返回 409）；未激活 marker 依赖即使声明了被拒绝的
  许可证也不会出现。
- 标识按字面、大小写敏感匹配：`mit` 不匹配策略中的 `MIT`（归为未知）；
  尾随 `+` 的 "or later" 标识（如 `Apache-2.0+`）是标识的一部分，需在
  策略中按完整字面列出才会命中。
- 输出只取决于快照、目标环境、锁定清单与 allow/deny 集合：两个列表按
  包名排序、路径按字典序排序，重复请求逐字节一致。

`/license-policy` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 锁有效，策略判定完成（存在违规或未知项仍是 200；`violations` / `unknowns` 同时为空表示全部允许） |
| `409` | 锁定清单未通过审计：`status: "invalid_lock"`，`issues` 与 `/audit-lock` 的输出一致（确定性排序），不解析许可证、不做判定；或某命中包的最短路径条数超过固定预算 1000：`status: "limit"`，含 `target`（按包名顺序命中的首个超限包）/ `used`（恒为 1001）/ `limit`，未构造路径列表 |
| `422` | 请求/快照非法（同 `/resolve`），或 `current_lock` 含非法 PEP 440 版本、某可达包锁定版本的 `metadata.license` 不是合法 SPDX `AND`/`OR`/括号表达式（含 `WITH`、`AND`/`OR` 任一侧缺少空白分隔，如 `MIT OR(Apache-2.0)`、`(MIT)AND(Apache-2.0)`）、`allow`/`deny` 项不是单个合法 SPDX 标识、`allow` 与 `deny` 存在重叠标识 |

### `POST /lock-diff`

用**同一份仓库快照与同一个目标环境**比较两份锁定清单
（`before_lock` → `after_lock`）。请求体沿用 `/resolve` 的 `repository` /
`root` / `target_environment` / `specifier` / `allow_prereleases`（语义
完全一致），并附加两份锁：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `before_lock` | `object` | 是 | 比较**基准**锁定清单：`{包名: 版本}`，格式同 `/audit-lock` 的 `current_lock` |
| `after_lock` | `object` | 是 | 比较**目标**锁定清单：格式同 `before_lock` |

处理流程：

1. **两份锁各自独立复用 `/audit-lock` 的同一套规则校验**（同一份快照、
   同一目标环境、同一根约束与 marker 激活语义）。即使某一份已经无效，
   另一份仍照常审计；
2. **任一份锁无效即整体返回 409**，响应分别标注 `before` 与 `after` 的
   审计结果（各为 `{"valid", "issues"}`，`issues` 与 `/audit-lock`
   逐字节一致、确定性排序），**不执行任何差异比较**；
3. 两份锁均有效时**不做任何版本选择**：分别按各自锁定版本展开已激活
   依赖，构造两张与 `/dependency-paths` 同语义的根可达图（未激活 marker
   依赖不是图的边），只比较两张图的**根可达包**集合与锁定版本：

   | 分类 | 判定 |
   | --- | --- |
   | `added` | 仅在 after 根可达（`before_version` 为 `null`，`before_paths` 为 `[]`） |
   | `removed` | 仅在 before 根可达（`after_version` 为 `null`，`after_paths` 为 `[]`） |
   | `upgraded` | 两侧均可达，after 锁定版本**严格高于** before（PEP 440） |
   | `downgraded` | 两侧均可达，after 锁定版本**严格低于** before（PEP 440） |

   PEP 440 等价版本（`1.0` 与 `1.0.0`）不产生变化项；根包本身发生
   升降级时同样进入 `upgraded` / `downgraded`（其最短路径为单节点
   `[根包]`）。

响应字段：

| 字段 | 说明 |
| --- | --- |
| `status` | 固定 `"ok"` |
| `root` | 规范化（PEP 503）后的根包名 |
| `added` / `removed` / `upgraded` / `downgraded` | 四类变化列表，各自**按规范化包名排序**；无变化时为 `[]` |
| 每类列表项 `name` | PEP 503 规范化包名 |
| `before_version` / `after_version` | 前后锁中的 PEP 440 版本字符串；added/removed 时缺失一侧为 `null` |
| `before_paths` / `after_paths` | 该包在**前 / 后依赖图**中从根包出发的**全部最短包路径**（与 `/dependency-paths` 同语义：含首尾、菱形等长路径全保留、环安全、字典序确定性排序）；该包在对应一侧**不存在时为空数组 `[]`**。变化项按 added → removed → upgraded/downgraded、各按包名的既有顺序逐个查询路径，某条查询的条数超过固定预算 1000 时整体返回 **409 / `status:"limit"`**（命中首个超限项），不构造任何路径列表 |

```bash
curl -s -X POST http://localhost:8000/lock-diff \
  -H 'Content-Type: application/json' \
  -d @examples/lock-diff.json
```

示例中 after 相对 before：`web-framework 2.4.0 → 3.2.0` 改拉
`telemetry-lib` 而不再依赖 `legacy-helper`（一增一删），`auth-lib
0.9.0 → 1.1.0` 新引入 `json-tool 1.0.0`（`<2.0`，降级通道的候选），
`shared-util 1.5.0 → 2.0.0` 同时经 `web-framework` 与 `auth-lib` 两条
等长菱形路径引入（两侧路径都返回）：

```json
{
  "status": "ok",
  "root": "app",
  "added": [
    {
      "name": "json-tool",
      "before_version": null,
      "after_version": "1.0.0",
      "before_paths": [],
      "after_paths": [["app", "auth-lib", "json-tool"]]
    },
    {
      "name": "telemetry-lib",
      "before_version": null,
      "after_version": "1.0.0",
      "before_paths": [],
      "after_paths": [["app", "web-framework", "telemetry-lib"]]
    }
  ],
  "removed": [
    {
      "name": "legacy-helper",
      "before_version": "0.5.0",
      "after_version": null,
      "before_paths": [["app", "web-framework", "legacy-helper"]],
      "after_paths": []
    }
  ],
  "upgraded": [
    {
      "name": "auth-lib",
      "before_version": "0.9.0",
      "after_version": "1.1.0",
      "before_paths": [["app", "auth-lib"]],
      "after_paths": [["app", "auth-lib"]]
    },
    {
      "name": "shared-util",
      "before_version": "1.5.0",
      "after_version": "2.0.0",
      "before_paths": [
        ["app", "auth-lib", "shared-util"],
        ["app", "web-framework", "shared-util"]
      ],
      "after_paths": [
        ["app", "auth-lib", "shared-util"],
        ["app", "web-framework", "shared-util"]
      ]
    },
    {
      "name": "web-framework",
      "before_version": "2.4.0",
      "after_version": "3.2.0",
      "before_paths": [["app", "web-framework"]],
      "after_paths": [["app", "web-framework"]]
    }
  ],
  "downgraded": []
}
```

任一份锁无效时返回 **409**，`before` / `after` 分别给出该侧的独立审计
结果（即使只有一侧无效，另一侧也带 `"valid": true, "issues": []`）：

```json
{
  "status": "invalid_lock",
  "message": "锁定清单未通过审计，未执行差异比较：before_lock、after_lock 无效",
  "before": {
    "valid": false,
    "issues": [
      {
        "type": "missing",
        "name": "req",
        "locked_version": null,
        "available": ["1.0"],
        "constraints": [
          {"from": "app==1.0", "specifier": "*"}
        ]
      }
    ]
  },
  "after": {
    "valid": false,
    "issues": [
      {
        "type": "extraneous",
        "name": "ghost",
        "locked_version": "9.9",
        "available": [],
        "constraints": []
      }
    ]
  }
}
```

确定性细节：比较只覆盖两张图的**根可达包**（锁中的不可达包会先在审计
阶段以 `extraneous` 报出）；四个列表按规范化包名排序、路径按字典序
排序，交换两份锁的提交位置时 `added` 与 `removed`、`upgraded` 与
`downgraded` 对称互换，结果与包键 / 候选列表 / 锁键的输入顺序无关。

`/lock-diff` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 两份锁均通过审计，差异比较完成（四类变化全为空表示根可达集与版本完全一致） |
| `409` | `before_lock` / `after_lock` 任一未通过审计：`status: "invalid_lock"`，`before` / `after` 分别携带与 `/audit-lock` 一致的确定性排序问题，不执行比较；或某变化项的最短路径条数超过固定预算 1000：`status: "limit"`，含 `target`（按 added → removed → upgraded/downgraded、各按包名的既有顺序命中的首个超限包）/ `used`（恒为 1001）/ `limit`，未构造路径列表 |
| `422` | 请求/快照非法（同 `/resolve`），或 `before_lock` / `after_lock` 含非法 PEP 440 版本、同一规范化包名对应多个不同版本 |

### `POST /explain-version`

**反事实版本解释**：把某个包强制钉在指定版本上，回答“锁会变成什么样、
为什么办不到”。请求体包含 `/resolve` 的全部字段（`repository` / `root` /
`target_environment` / `specifier` / `allow_prereleases`，语义完全一致），
并附加两个字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `target_package` | `string` | 是 | 要解释的目标包名（PEP 503 规范化匹配）；**必须出现在基准锁定清单中**（从根包可达），否则返回 422 |
| `target_version` | `string` | 是 | 强制目标包使用的 PEP 440 版本；非法版本返回 422，响应中回显规范化形式 |

处理流程：

1. **基准锁**：按 `/resolve` 原规则对请求求解（同一快照、同一目标环境、
   同一根约束与 marker/预发布语义）。基准本身无解时直接返回该次求解的
   **409** 冲突结果（与单独调用 `/resolve` 一致），不做任何反事实求解；
2. **可达性检查**：`target_package` 不在基准锁定清单中（即从根包不可达）
   时返回 **422**；
3. **反事实求解**：其余规则不变，仅以一条与根需求并列的根级
   `==target_version` 约束钉住目标包后整体重解（MRV、高版本优先、回溯、
   预发布跟随语义、尝试上限均与 `/resolve` 相同；显式 `==预发布` 钉版本
   时该预发布仍被接受）。**不可行时返回 409**，复用约束来源链说明阻塞
   原因——钉版本约束本身也作为一条根级来源链出现；
4. **可行时返回 200**：反事实锁定清单，以及相对基准锁的三类差异
   （均按规范化包名排序）：

   | 分类 | 判定 |
   | --- | --- |
   | `added` | 仅在反事实锁中出现的包（`version` 为新锁版本） |
   | `removed` | 仅在基准锁中出现的包（`version` 为基准版本） |
   | `changed` | 两侧都锁定但版本不同的包（`from` 基准版本 → `to` 新版本，含目标包本身） |

   PEP 440 等价版本（`1.0` 与 `1.0.0`）不产生 `changed` 项；强制版本与
   基准锁一致时三类差异均为 `[]`。

```bash
curl -s -X POST http://localhost:8000/explain-version \
  -H 'Content-Type: application/json' \
  -d @examples/explain-version.json
```

示例沿用 `/lock-diff` 示例的快照：基准锁中 `web-framework` 为 `3.2.0`
（拉入 `telemetry-lib`，`shared-util` 锁在 `2.0.0`）。强制
`web-framework==2.4.0` 后它改拉 `legacy-helper` 而不再依赖
`telemetry-lib`，`shared-util` 随之回落到 `1.5.0`：

```json
{
  "status": "ok",
  "root": "app",
  "root_version": "1.0.0",
  "target_package": "web-framework",
  "target_version": "2.4.0",
  "baseline_locked": {
    "app": "1.0.0",
    "auth-lib": "1.1.0",
    "json-tool": "1.0.0",
    "shared-util": "2.0.0",
    "telemetry-lib": "1.0.0",
    "web-framework": "3.2.0"
  },
  "locked": {
    "app": "1.0.0",
    "auth-lib": "1.1.0",
    "json-tool": "1.0.0",
    "legacy-helper": "0.5.0",
    "shared-util": "1.5.0",
    "web-framework": "2.4.0"
  },
  "added": [
    {"name": "legacy-helper", "version": "0.5.0"}
  ],
  "removed": [
    {"name": "telemetry-lib", "version": "1.0.0"}
  ],
  "changed": [
    {"name": "shared-util", "from": "2.0.0", "to": "1.5.0"},
    {"name": "web-framework", "from": "3.2.0", "to": "2.4.0"}
  ]
}
```

- `baseline_locked`：按 `/resolve` 原规则求出的基准锁定清单（差异比较的基准）。
- `locked`：强制目标版本后的**完整**反事实锁定清单（按规范化包名排序）。
- `added` / `removed` / `changed`：相对基准锁的差异，各自**按包名排序**；
  目标版本高于或低于基准均可（与 `/upgrade` 不同，不做方向限制，也不做
  变更最小化——返回的是确定性求解顺序下的首个可行解）。

反事实无解时返回 **409**，`conflicts` 与 `/resolve` 的 409 完全同形：
钉版本约束以根级来源链（`package: null`、`requires: "==版本"`）出现，
阻塞它的传递约束各附完整来源链：

```bash
curl -s -X POST http://localhost:8000/explain-version \
  -H 'Content-Type: application/json' \
  -d @examples/explain-version-conflict.json
```

示例沿用 `/resolve` 成功示例的快照：强制 `shared-util==2.0.0` 与
`auth-lib 0.9.0` 的 `<2.0` 约束冲突（`auth-lib` 别无候选），整体无解：

```json
{
  "status": "conflict",
  "message": "无法将目标包 'shared-util' 强制为 2.0.0：该版本下依赖约束无解",
  "conflicts": [
    {
      "subject": "shared-util",
      "kind": "no_candidates",
      "message": "包 shared-util 在约束交集 <2.0,==2.0.0 下没有可满足的版本；快照中的版本（降序）：2.0.0, 1.5.0, 1.4.0",
      "constraints": [
        {"chain": [
          {"package": null, "version": null, "requires": "*"},
          {"package": "app", "version": "1.0.0", "requires": "*"},
          {"package": "auth-lib", "version": "0.9.0", "requires": "<2.0"}
        ]},
        {"chain": [
          {"package": null, "version": null, "requires": "==2.0.0"}
        ]}
      ],
      "partial_selection": {"app": "1.0.0", "auth-lib": "0.9.0"}
    }
  ]
}
```

`/explain-version` 的状态码：

| 状态码 | 含义 |
| --- | --- |
| `200` | 反事实求解可行，返回基准锁、新锁与 added/removed/changed |
| `409` | 基准锁无解（与 `/resolve` 的 409 一致）；或强制目标版本后无解（`status: "conflict"`，附约束来源链）；或搜索超过内置尝试上限（`status: "limit"`） |
| `422` | 请求/快照非法（同 `/resolve`），或 `target_version` 不是合法 PEP 440 版本，或 `target_package` 不在基准锁定清单中（从根包不可达） |

---

## 三、解析规则说明

1. **包名规范化**：统一使用 PEP 503（`Some_Pkg`、`some.pkg`、`some-pkg` 视为同一个包）。
2. **环境标记（PEP 508）**：每条依赖的 `marker` 在请求提供的
   `target_environment` 上求值；只允许引用 `python_version` /
   `sys_platform` / `platform_machine`，求值环境不读取宿主机。仅激活的
   依赖进入后续全部求解流程（约束收集、回溯、来源链、`edges`）。
3. **约束交集**：对每个包收集所有激活的传递路径上的 PEP 440 约束，必须同时满足。
4. **选择次序**：在所有未决包中优先展开“可满足候选最少”的包（MRV），
   名称次序兜底；具体候选严格从高版本到低版本尝试。
5. **回溯**：候选版本展开后若与后续传递依赖冲突，放弃该版本，尝试下一个更低版本；
   每次尝试在独立的状态克隆上进行，失败不会污染其他分支。
6. **环处理**：已选定的包被再次要求时只校验约束、不重复展开，因此环不会无限递归；
   若环上带来矛盾约束，按 `incompatible` 报出。
7. **预发布**：默认排除 `a/b/rc/dev`；`allow_prereleases=true` 放开；
   或约束显式钉住预发布（如 `==2.0rc1`）时也会被接受。
8. **确定性**：候选按 PEP 440 降序、输出按键排序，重复解析同一快照与环境结果逐字节一致。
9. **升级（`/upgrade`）**：在 `/resolve` 语义上附加 `current_lock` 与 `target`。
   目标包只尝试严格高于当前版本的候选（高版本优先），取第一个能完成整体
   解析的版本；随后在该版本的所有有效解中枚举并保留“非目标包相对
   `current_lock` 变化数量最少”的解（分支定界剪枝，变化数相同按既定
   确定性顺序取先遇到者）。`/resolve` 的行为不受任何影响。
10. **审计（`/audit-lock`）**：不求解，只按 `current_lock` 的锁定版本从根包
    遍历已激活依赖：环中包只展开一次但累计全部入边约束；输出
    missing / unavailable / constraint_mismatch / extraneous 四类确定性
    排序的问题，包名按 PEP 503、版本与约束按 PEP 440 判断。
11. **依赖路径（`/dependency-paths`）**：先复用第 10 条的审计，锁无效即
    返回 409 且不查询；锁有效时按锁定版本展开已激活依赖建图，BFS 返回根包
    到目标包的全部最短包路径：菱形等长路径全保留，环不重复节点、不会无限
    遍历，路径按字典序确定性排序；目标为根包返回单节点路径，不可达返回
    `reachable: false` 与空路径。最短路径条数受固定预算 1000 约束：BFS
    建立最短前驱图后先按层做饱和计数，条数超限（饱和为 1001）即返回
    409 `status:"limit"`，不构造路径列表。
12. **安装计划（`/install-plan`）**：先复用第 10 条的审计，锁无效即
    返回 409 且不生成批次；锁有效时只对根可达包按锁定版本的已激活依赖
    建图（与第 11 条同一张图，无版本选择），用 Kosaraju 算法求强连通
    分量并把每个分量收缩为一个节点得到 DAG（多成员分量与自环标为循环
    分量，同一分量须作为一个原子安装项），再在 DAG 上按最长路径分层
    （层号 = 各依赖分量层号最大值 + 1）输出依赖优先的并行安装批次：
    同一批内各项互不依赖可并行，任一依赖所在批次严格早于依赖它的包，
    根包可达全部节点故根包所在分量处于最后一批。批次按层号、批内单包
    按包名、循环分量按内部包名元组字典序排序，循环分量内部包名排序，
    输出与输入顺序无关。
13. **跨环境矩阵（`/resolve-matrix`）**：对同一份快照与根约束，在 2～8 个
    带唯一 `id` 的目标环境上**按 `id` 升序的稳定顺序**各跑一遍第 2～8 条的
    同一套求解（环境间完全独立、各自回溯与冲突收集），各环境候选尝试次数
    累计计入请求级共享预算（`MATRIX_ATTEMPT_LIMIT`，默认 800,000；预算
    耗尽立即停止后续环境，返回顶层 409 `status:"limit"`、触发环境与
    used/limit）。全部成功时 `results` 按 `id` 排序给出各环境锁定清单，
    `matrix` 按包名排序逐包记录各环境版本（未出现为 `null`）：所有环境都
    存在且版本一致为 `shared`，否则（版本不同或仅部分环境出现）为
    `divergent`；任一环境无解则整体 409，`failures` 按 `id` 排序给出各
    失败环境与 `/resolve` 同形的原冲突结果（环境自身超尝试上限也在
    `failures` 内、继续跑完全部环境）。
14. **物料清单（`/sbom`）**：先复用第 10 条的审计，锁无效即返回 409 且不
    导出；锁有效时沿第 11 条的已激活依赖图（按锁定版本、无版本选择）逐包
    导出规范化名称、版本、PURL（`pkg:pypi/<name>@<version>`）、已激活
    依赖名称（去重排序）与候选版本携带的 `source_url` / `sha256` /
    `license` 元数据；元数据缺失不阻断导出，只在 `warnings` 中按包名逐项
    提示；`packages` 按包名排序，输出只取决于快照、环境与锁。
15. **许可证策略（`/license-policy`）**：先复用第 10 条的审计，锁无效即
    返回 409 且不判定；锁有效时在第 11 条的已激活依赖图上逐包读取锁定
    版本的 `metadata.license`：未提供归为未知（不阻断），提供则解析
    SPDX `AND`/`OR`/括号表达式（`OR` 低于 `AND`，括号分组；关键字大小
    写不敏感、标识大小写敏感），按 allow/deny 两个标识集合做三态求值——
    标识在 deny 中为拒绝、仅在 allow 中为允许、其余未知；`AND` 全部允许
    才通过、任一拒绝即违规；`OR` 任一允许即通过、全部拒绝才违规、其余
    未知。词法分析保留运算符两侧必须以空白分隔的 SPDX 规则（靠记号位置
    校验而非 split，优先级与嵌套括号不受影响）：`MIT OR(Apache-2.0)`、
    `(MIT)AND(Apache-2.0)` 等紧贴写法稳定报 422 并在错误信息中定位违规
    运算符与位置；标识词中的 AND/OR 字母片段（如 `ANDOR`）不被拆分。
    `violations` 与 `unknowns` 各自按包名排序，每项复用第 11 条的最短
    路径算法附根包到该包的全部最短路径（同受固定条数预算 1000 约束：
    命中包按包名顺序逐个查询，首个超限项即整体返回 409 `status:"limit"`）；
    非法 SPDX 表达式（含 `WITH`、运算符缺空白）、allow/deny 非法标识或
    两集合重叠返回 422，输出确定。
16. **锁差异比较（`/lock-diff`）**：同一份快照与目标环境下提交
    before_lock / after_lock，两份锁**各自独立**复用第 10 条的审计
    （即使一份已无效仍审计另一份），任一无效即整体 409 且分别标注
    before/after 的问题、不做比较；均有效时在两张第 11 条的已激活依赖
    图上只比较**根可达包**：after 独有为 added、before 独有为 removed、
    两侧均有则按 PEP 440 版本方向分为 upgraded / downgraded（等价版本
    不产生变化项）；每个变化项分别复用第 11 条的最短路径算法给出其在
    前后图中的全部最短根路径（同受固定条数预算 1000 约束：变化项按
    added → removed → upgraded/downgraded、各按包名的既有顺序逐个查询，
    首个超限项即整体返回 409 `status:"limit"`），不存在的一侧为空数组；
    四类列表各按包名排序、路径按字典序排序，交换提交位置结果对称，
    与输入顺序无关。
17. **反事实版本解释（`/explain-version`）**：先按第 2～8 条的原规则求出
    基准锁定清单（基准无解即返回该次求解的 409）；目标包不在基准锁中
    （从根包不可达）返回 422。随后其余规则不变，仅以一条与根需求并列的
    根级 `==target_version` 约束钉住目标包整体重解（显式钉预发布时该
    预发布仍被接受，其余预发布语义不变）：可行时返回新锁与相对基准锁的
    added / removed / changed（PEP 440 等价版本不产生 changed 项，三个
    列表均按包名排序）；不可行时返回 409，复用第 2～8 条的约束来源链
    说明阻塞原因，钉版本约束本身作为一条根级来源链出现。两次求解各自
    使用独立的求解器实例，互不影响冲突收集与尝试计数。
18. **最少锁组（`/lock-groups`）**：请求与第 13 条的 `/resolve-matrix`
    相同。先**按 `id` 升序的稳定顺序**逐环境复用第 2～8 条各求一份候选锁
    （与第 13 条共用同一个请求级共享预算：任一环境无解即整体 409 并按 id
    排序保留各失败环境与 `/resolve` 同形的原冲突结果、继续跑完其余环境；
    共享预算耗尽则立即停止后续求解，返回顶层 409 `status:"limit"`）；全部
    有解后候选锁按锁内容（规范化包名 → 版本）去重，每份候选锁在每个环境上
    再按第 10 条的同一套审计规则交叉校验（marker 按被审计环境求值；无任何
    审计问题才可覆盖该环境）。随后在至多 8 份候选锁上枚举全部子集，精确取
    并集覆盖全部环境且锁文件数量最少者；并列最优按锁内容（逐 (包名, 版本)
    对字典序）与环境 id（升序）的稳定序裁决。响应的每个锁组含由锁内容
    SHA-256 派生的稳定 id、按 id 排序的覆盖环境列表与按包名排序的锁内容，
    锁组按稳定 id 排列；结果只取决于快照、根约束与环境集合，与环境提交
    顺序无关（含共享预算的截断位置）。

### 安全护栏

- **尝试上限**（单环境默认 100,000 次候选展开）：防止恶意构造的快照造成指数级搜索，
  超出返回 `409 / status:"limit"`；该上限对每个求解器实例独立生效，`/resolve`
  及 `/resolve-matrix`、`/lock-groups` 中的每个环境都保留这一既有语义。
- **请求级共享求解预算**（`/resolve-matrix`、`/lock-groups`，默认 800,000 次，
  环境变量 `MATRIX_ATTEMPT_LIMIT` 配置）：同请求各环境的候选尝试累计计数，
  超限立即停止后续环境求解并返回 `409 / status:"limit"`（触发环境、已用次数、
  上限）；非法配置在启动时失败。环境按 `id` 稳定顺序执行，输入重排不改变
  截断位置与响应。详见上文 `/resolve-matrix` 的“请求级求解预算”。
- **依赖链深度上限**（默认 5,000 层）：超出同样以 `limit` 报出，而不是进程栈溢出。
- **最短路径条数预算**（`/dependency-paths`、`/license-policy`、`/lock-diff`
  共用，固定 1,000 条，不随配置变化）：分层菱形依赖下根到目标的最短路径
  条数随层数指数增长，逐一构造路径列表会拖垮进程。BFS 建立最短前驱图后
  先按层做**饱和计数**（只累加条数、不构造路径），条数超过预算即饱和为
  1,001 并返回 `409 / status:"limit"`（含目标包、`used: 1001`、
  `limit: 1000`），不构造路径列表；一次请求涉及多个目标时按既有包名顺序
  稳定命中首个超限项。未超限的查询行为完全不变（全部最短路径照常返回）。

## 四、项目结构

```
app/
  main.py           # FastAPI 路由与错误映射
  config.py         # 环境变量配置（MATRIX_ATTEMPT_LIMIT 请求级共享求解预算，启动时校验）
  resolver.py       # 回溯求解器（候选排序 / MRV / 来源链重建 / 跨环境共享尝试预算）
  audit.py          # 锁定清单审计（按锁版本遍历 / 环中累计入边 / 四类问题）
  paths.py          # 锁定依赖图建图与根包到目标包的全部最短路径（菱形/环安全，固定条数预算 1000 + 按层饱和计数）
  install_plan.py   # 有效锁图 SCC 压缩为 DAG 与依赖优先并行安装批次（循环分量原子项）
  sbom.py           # 沿已激活依赖图导出确定性 JSON SBOM（PURL / 元数据 / 缺失 warnings）
  spdx.py           # SPDX 许可证表达式词法/递归下降解析与 allow/deny 三态求值
  license_policy.py # 有效锁图上的逐包许可证策略判定（违规/未知 + 全部最短路径）
  lock_diff.py      # 两份有效锁的根可达包差异（added/removed/upgraded/downgraded + 双侧最短路径）
  lock_groups.py    # 跨环境最少锁组选择（候选锁交叉审计 + 精确最小集合覆盖 + 稳定裁决）
  repository.py     # 快照规范化、PEP 440/503 解析、按环境过滤 marker、候选元数据校验
  markers.py        # PEP 508 marker 解析/白名单校验/环境求值（不读宿主机）
  schemas.py        # 请求/响应模型
examples/            # curl 示例请求体（含跨环境 marker、/resolve-matrix、/lock-groups、/upgrade、/audit-lock、/dependency-paths、/install-plan、/sbom、/license-policy、/lock-diff、/explain-version 示例）
tests/               # 求解器与 HTTP 层测试（pytest + FastAPI TestClient）
Dockerfile
docker-compose.yml
requirements.txt
```

## 五、运行测试

```bash
.venv/bin/pip install pytest httpx
.venv/bin/python -m pytest -q
```
