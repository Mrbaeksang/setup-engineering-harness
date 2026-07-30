# Engineering Harness 설계

상태: accepted

범위: `setup-engineering-harness` 설치기와 설치 결과

기본 provider: Codex

## 목적

이 프로젝트는 특정 앱 템플릿을 설치하지 않는다. 한 Coding Agent가 사용자의 요구와
현재 Project에 맞춰 다음을 일관되게 수행하도록 만드는 범용 Harness다.

1. 요구사항에서 실제로 결과를 바꾸는 미결정만 묻는다.
2. 독립 질문은 한 번에 묶고, 답에 따라 다음 선택지가 달라지는 질문만 순차적으로
   묻는다.
3. 기존 Project를 먼저 조사하고 충분한 현재 스택은 유지한다.
4. greenfield나 명시적 stack 변경은 같은 기준으로 현재 후보 2–3개를 비교한다.
5. 모델 기억을 가설로 취급하고 exact version과 최신 공식 자료를 다시 확인한다.
6. 작은 버그부터 큰 기능까지 작업 크기에 비례해 계획·문서·검증을 조절한다.
7. 사용자의 자연어 확인을 그대로 이해한다. 별도 Task ID, hash, proposal ID, magic
   phrase를 기본 UX로 요구하지 않는다.
8. 단순 작업에 회의록, 진행 보고서, 연구 덤프, 형식적 spec/ticket을 만들지 않는다.

Setup Skill은 이 동작을 기존 Project에 한 번에 설치하며 앱 코드를 변경하지 않는다.

## 제품 원칙

### Stack-neutral

Harness는 Next.js, FastAPI, DDD, hexagonal architecture 같은 선택을 기본값으로 밀지
않는다. Project에 이미 있는 경계와 exact version을 먼저 찾는다. 새 선택이 필요하면
제품/운영 기준을 먼저 합의하고 현재 공식 자료로 후보를 비교한다.

### Version-correct

라이브러리·framework·SDK·API 작업의 evidence ladder는 다음과 같다.

1. lockfile, installed metadata, runtime/tool output으로 exact version 확인
2. 그 version에 맞는 primary official docs와 migration/release notes 확인
3. 좁은 public types, exports, installed source 확인
4. 최소 reproduction
5. native supported capability 우선

기억 속 API가 이전 major에 해당하면 그대로 생성하지 않는다. 선택한 version의 공식
문서와 migration을 다시 읽고 현재 API를 사용한다.

### Adaptive

| 작업 크기 | 기본 흐름 |
| --- | --- |
| 작은 버그/수정 | reproduce → fix → regression → verify |
| 중간 기능 | align → research → compact spec → implement → verify |
| 큰/고비용 결정 | deep align → research → user choice → compact spec → tracer-bullet slices |

분류는 줄 수가 아니라 불확실성, 경계 수, 되돌리기 비용, 외부 계약, 위험으로 한다.

### Artifact on demand

- 단순 작업: 별도 문서 없음
- 중간 작업: 대화 안의 compact spec
- 지속될 domain/architecture 결정: 기존 canonical CONTEXT/ADR 갱신
- 여러 context·사람·시스템에 걸친 큰 작업: 합의된 tracer-bullet ticket
- research notes: 기본 ephemeral

## 설치 구조

```text
Project
├── AGENTS.md 또는 CLAUDE.md       Managed Bridge
├── provider Hook 설정             기존 Hook과 병합
└── .agent-harness/
    ├── config.json                 user-owned, seed once
    ├── local.md                    user-owned, seed once
    ├── repo-profile.json           installer-owned, regenerable
    ├── router.md                   progressive Playbook routing
    ├── playbooks/
    │   ├── core.md
    │   ├── conversation.md
    │   ├── dependencies.md
    │   ├── planning.md
    │   ├── implementation.md
    │   ├── architecture.md
    │   ├── verification.md
    │   ├── documentation.md
    │   └── safety.md
    ├── bin/                        optional helpers/strict compatibility
    ├── checks/audit.py
    └── manifest.json

XDG state directory
├── trusted Hook runtime
├── provider verification status
└── strict-mode lifecycle state
```

Managed Bridge는 짧게 유지한다. 항상 Project Profile과 사용자 소유 제약을 읽고,
Task signal에 맞는 Playbook만 점진적으로 읽는다.

## Hook 모드

### Assistive — 기본값

`write_gate.mode`가 없거나 `"assistive"`면:

- UserPromptSubmit은 lifecycle state를 만들거나 갱신하지 않는다.
- Task ID, acceptance hash, Decision ID, proposal, lease command를 주입하지 않는다.
- 현재 Project/greenfield 판단, 질문 방식, version research, adaptive workflow,
  artifact policy, verification 규칙만 짧게 주입한다.
- 일반 shell, app write, web, Context7, ImageGen과 future specialized tools를 blanket
  deny하지 않는다.
- 다른 Project cwd의 호출에는 no-op한다.

PreToolUse Hook이 직접 막는 범위:

- `.env*`, private key/credential/secret 파일의 native write
- `.agent-harness/**`, `.git/**`
- `.codex/hooks.json`, `.claude/settings.json`
- `.engineering-harness-provider-canary`
- malformed native write/patch payload

일반 shell 실행과 specialized tool의 실제 권한은 Codex의 permission/sandbox가
담당한다. Hook은 모든 가능한 side effect를 추측하는 security theater를 만들지 않는다.

### Strict — 명시적 호환 모드

`write_gate.mode = "strict"`를 선택한 Project는 기존 구조화 acceptance, Evidence,
Decision, scoped Write Lease, brokered verification lifecycle을 사용한다. 이는 기본
대화 UX가 아니며 높은 통제가 필요한 Project를 위한 호환 경로다.

기존 mode 없는 user-owned config도 assistive로 해석한다. 설치기는 user-owned config를
덮어쓰지 않는다.

## 대화 계약

Coding Agent는 먼저 repository facts로 답할 수 있는 문제를 해결한다. 질문이 필요하면:

- behavior, architecture, cost, security, external contract, irreversible choice에 영향을
  주는 것만 묻는다.
- 서로 독립인 질문은 한 번호 묶음으로 보낸다.
- 의존 질문은 이전 답을 받은 뒤 묻는다.
- 각 선택지는 같은 비교 차원을 사용하고 실제 tradeoff를 밝힌다.
- recommendation은 options와 분리해 근거를 말한다.
- 미결정이 없으면 reversible assumption을 밝히고 진행한다.

`ㅇㅇ`, `그렇게 해`, `yes`, `go ahead` 같은 표현은 referent가 분명하면 유효한 확인이다.
문구가 다르다는 이유로 사용자를 다시 승인 루프에 넣지 않는다.

## Stack 선택 계약

### Existing Project

1. instructions, manifests, lockfiles, exact installed versions, source, tests, CI를 제한적으로
   조사한다.
2. 현재 stack이 요구를 만족하면 유지한다.
3. native capability를 wrapper나 새 dependency보다 먼저 찾는다.
4. upgrade는 capability, compatibility, security, support 이유가 명확할 때만 제안한다.
5. upgrade 시 crossed migration range를 검증한다.

### Greenfield 또는 명시적 변경

1. 요구사항에서 평가 기준을 만든다.
2. 최신 primary official sources로 후보 2–3개를 조사한다.
3. stable version, runtime/support policy, capability, ecosystem, deployment, asset/tooling,
   team constraints를 같은 표면에서 비교한다.
4. 되돌리기 어려운 선택이면 user choice를 받는다.
5. 선택 뒤 그 exact version의 docs/migration/types를 다시 읽고 구현한다.

## 계획과 구현

Compact spec에는 필요한 경우에만 다음을 둔다.

- outcome과 observable acceptance
- exclusions와 assumptions
- affected behavior/boundaries
- exact stack/version facts와 research 결정
- verification seams

큰 작업은 horizontal layer ticket이 아니라 end-to-end tracer bullet로 나눈다. 각 slice는
작은 사용자 가치를 전달하고 독립 검증 가능하며 Project를 runnable 상태로 남긴다.
한 slice씩 구현하고 좁은 검증을 거친다.

## 검증

완료 주장은 fresh observation에만 근거한다.

1. 가능한 경우 failure/baseline 재현
2. 바뀐 public behavior를 직접 다루는 narrow regression
3. risk에 비례한 repository-native test/type/lint/build/integration/UI/performance checks
4. `git status`와 diff로 scope, style, noise, secret exposure 확인
5. Harness/instruction 변경일 때만 `python3 .agent-harness/checks/audit.py`

Project Profile의 command는 detected candidate이지 실행 결과가 아니다. 실행하지 않은
검증은 PASS라고 말하지 않는다.

## 설치·소유권·복구

- Python 3.12+ standard library만으로 plan/install/audit/repair/uninstall 가능
- install 전 plan은 read-only
- 기존 instructions와 unrelated hooks 보존
- installer-owned 파일 drift 시 install 중단
- repair는 content-addressed recovery copy를 만든 뒤 명시적으로 복구
- repeated install은 byte-identical
- uninstall은 managed content만 제거하고 user-owned/unknown 파일 보존
- install/repair는 앱 코드, Project dependency, secret, Project command를 건드리지 않음

## Provider canary

`verify-provider`는 fresh provider session에서
`.engineering-harness-provider-canary` native write를 한 번 시도한다. provider Hook이
실제로 deny해야 PASS다. sandbox 자체 deny나 simulated replay는 대체 evidence가 아니다.
canary 전후 runtime/lifecycle state는 보존하고 reserved file이 남으면 실패한다.

## 테스트 전략

- assistive unit: normal shell/app write/specialized tools allow, protected paths/canary deny,
  other Project no-op
- strict conformance: canonical/bundled adapter와 lifecycle 회귀
- installer: plan/install idempotence, preservation, repair, uninstall, user-owned config
- provider: real canary receipt와 audit binding
- distribution: packaged Skill asset completeness
- regression: natural later-user answer handling in strict compatibility mode

완료 조건은 전체 Python/npm suite, distribution verification, 설치 fixture의 audit, 가능한
환경에서 real provider canary가 모두 관찰된 결과로 남는 것이다.

## 알려진 한계

- thin assistive Hook은 future specialized tool의 side effect를 완전 분류하지 않는다.
- provider sandbox/permission 설정이 normal execution의 실질 boundary다.
- clean-context benchmark는 방향성 evidence이며 통계적 제품 품질 증명이 아니다.
- strict runtime은 호환성 때문에 크지만 assistive 기본 경로에서는 사용되지 않는다.
