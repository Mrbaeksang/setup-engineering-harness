# Setup Engineering Harness

이 문서는 현재 구현의 제품 계약, 구조, 검증 근거를 한 곳에서 관리하는
canonical 문서다. 진행 일지나 미래 로드맵이 아니다.

## 한 문장 정의

기존 저장소에 한 번 Setup하면, 사용자가 대화하는 **하나의 코딩 AI**가
질문·조사·구현·검증·문서화를 증거 우선 방식으로 수행하도록 자동 안내하고
중요한 전환은 코드로 강제하는 Engineering Harness다.

## 요구사항 해석

지금 만드는 것은 멀티에이전트 관리자나 Chief of Staff 제품이 아니다.
현재 세션의 코딩 AI 자체를 더 정확하게 만드는 저장소용 Harness다.

사용자가 기대하는 행동은 다음과 같다.

1. 구현 결과를 바꾸는 정보가 없으면 먼저 묻는다.
2. 질문은 독립적인 항목을 한 번에 묶고, 객관적인 A/B/C 선택지를 준다.
3. 추천이 있으면 중립적인 선택지와 추천 근거를 분리한다.
4. 설치된 정확한 버전과 해당 버전의 문서·타입·소스를 모델 기억보다
   우선한다.
5. 라이브러리 기본 기능을 확인하기 전에는 커스텀 우회 코드를 쓰지 않는다.
6. 작은 작업은 작게 처리하고, 위험과 모호성이 큰 작업만 절차를 확장한다.
7. DDD, 모듈성, 헥사고날 경계를 기본 사고법으로 사용하되 의미 없는
   물리 계층은 만들지 않는다.
8. diff, 테스트, 측정 같은 실행 증거 없이 완료를 주장하지 않는다.
9. 에이전트가 읽을 문서는 짧고 계층적이어야 하며, 같은 사실을 여러 문서에
   복제하지 않는다.
10. 이 행동은 사용자가 매번 프롬프트로 상기시키지 않아도 자동으로
    적용되어야 한다.

## Assumptions

- 로컬 우선, 단일 사용자, Git 저장소를 기준으로 한다.
- 현재 설치 가능한 provider 경계는 Codex project hook이다.
- Python 3.12 표준 라이브러리만으로 Setup과 host runtime을 실행한다.
- Linux/WSL에서는 `bubblewrap`, macOS에서는 `sandbox-exec`이 있어야
  관리형 검증을 완료 증거로 사용할 수 있다.
- 앱 저장소의 기존 규칙과 사용자가 소유한 설정은 Setup보다 우선한다.
- 공개 저장소이며 Apache License 2.0으로 배포한다.

## 현재 범위와 경계

현재 구현은 다음을 포함한다.

- 결정적인 `plan`, `install`, `verify-provider`, `audit`, `repair`,
  `uninstall`
- 기존 `AGENTS.md`와 `.codex/hooks.json`을 보존하는 managed merge
- manifest, lockfile, 검증 script, instruction 파일의 bounded profiling
- 얇은 instruction bridge와 task-triggered Playbook
- 검색·부분 읽기·얕은 구조 지도·안전한 Git diff를 제공하는 read broker
- 구조화된 acceptance contract, Evidence, Decision, scoped Write Lease
- dependency research와 architecture drift를 막는 fail-closed Gate
- 격리 snapshot에서만 실행되는 verification broker와 completion receipt
- control / stable / adaptive-R&D를 비교하는 benchmark 및 scoring runtime

현재 제품 경계 밖의 기능을 이 문서에 약속하지 않는다. 특히 이 구현은
멀티에이전트 세션 관리, TUI, daemon, 배포 자동화, vector memory,
범용 workflow engine이 아니다.

## 설계 후보와 선택

| 후보 | 장점 | 한계 | 판단 |
|---|---|---|---|
| 거대한 prompt 또는 `AGENTS.md`만 사용 | 가장 단순하고 즉시 적용 가능 | 우회 가능, 항상 긴 context, 검증 없는 완료를 막지 못함 | 제외 |
| Setup Skill + repo-local 문서만 사용 | Matt Pocock식 one-shot UX, Git에서 검토 가능, 점진적 문서 로딩 | 모델이 문서를 무시하면 쓰기와 완료를 막지 못함 | 단독 사용 제외 |
| **Setup Skill + thin bridge + host-side Gate + broker** | one-shot UX와 기계적 강제를 함께 제공, 상태를 앱 코드와 분리 | hook 신뢰와 OS 격리 기능에 의존, 구현 복잡도 증가 | **선택** |

선택 근거는 “좋은 지시”와 “강제 가능한 invariant”를 분리할 수 있기
때문이다. 질문의 문장이나 조사 순서는 Playbook에 둔다. 비밀 경로 접근,
acceptance 없는 쓰기, 범위 밖 편집, 검증 없는 완료는 Gate에 둔다.

## 행동 계약

### 대화

모호한 요청은 즉시 구현하지 않는다. 먼저 저장소 사실을 bounded하게
확인한 뒤 결과를 바꾸는 질문만 묻는다.

- 질문은 서로 의존하지 않는 것끼리 한 번에 묶는다.
- 선택지는 같은 비교 축을 가진 객관적인 A/B/C로 만든다.
- 선택지 안에 추천을 숨기지 않는다.
- 추천은 별도 문단에서 기준과 trade-off를 밝힌다.
- 이미 저장소나 사용자 답변으로 결정된 내용은 다시 묻지 않는다.
- 되돌리기 쉽고 사용자 경험에 영향이 없는 결정은 근거와 함께 자동으로
  처리한다.

### 의존성과 최신성

Dependency signal이 있으면 다음 순서로 좁혀 읽는다.

1. manifest와 lockfile
2. 설치된 정확한 버전
3. 그 버전에 맞는 공식 문서
4. migration guide와 changelog
5. 타입 정의
6. 설치된 소스
7. 공식 issue/discussion
8. 최소 재현과 변경 전후 검증

`latest`는 가장 높은 번호가 아니라 현재 안정성, 생태계 호환성, 배포
지원, 필요한 기능, migration 비용을 함께 만족하는 버전이다. 기존 기능이
요구사항을 해결하면 커스텀 memoization, cache, debounce, wrapper보다
우선한다.

### 설계와 구현

- acceptance outcome과 관찰 가능한 criterion을 먼저 고정한다.
- 예상 write path와 검증 명령을 선언한다.
- DDD 용어로 invariant와 경계를 찾는다.
- 실제 경계가 있을 때만 module/port/adapter를 물리적으로 만든다.
- 승인되지 않은 dependency, architecture 변경, 범위 밖 refactor는
  새 Decision으로 되돌린다.
- 유효한 Write Lease 범위 안에서만 수정한다.
- 가장 작은 증거 기반 변경을 우선한다.

### 검증과 완료

- 가능한 경우 실패하는 baseline을 먼저 재현한다.
- Project Profile에 등록된 정확한 command만 verification broker로
  실행한다.
- source-controlled 입력은 disposable snapshot에서 실행하고 network와
  외부 쓰기를 막는다.
- 구현 뒤 brokered `git-status`와 `git-diff`로 범위와 주변 style을
  확인한다.
- acceptance criterion마다 fresh receipt 또는 명시적인 사용자 Decision이
  있어야 한다.
- ordinary application change에는 Harness audit를 요구하지 않는다.
- Harness 또는 instruction 변경에는 Harness audit가 필요하다.
- 모든 현재 receipt가 implementation hash와 일치할 때만 completion
  receipt를 만들고 lease를 폐기한다.

### 문서

문서는 생성보다 승격을 우선한다.

- 안정된 용어: `CONTEXT.md`
- 설치·사용·현재 경계: `README.md`
- 제품 계약·구조·검증 근거: 이 문서
- Task 중간 로그, worker 보고, 임시 조사, raw output: 영구 Markdown으로
  만들지 않는다.
- 결정이 바뀌면 canonical 문서를 갱신하고 대체된 설명은 삭제한다.
- 미래 범위, 회의록, 진행 보고서, 동일 내용의 요약 문서를 누적하지 않는다.

## 구조

```text
사용자 Prompt
    │
    ▼
Codex UserPromptSubmit Hook
    ├── Task/Revision 생성 또는 갱신
    ├── 기존 Write Lease 폐기
    └── bounded Context Pack 주입
             │
             ▼
        Coding Agent
        ├── read broker ───────────────┐
        ├── lifecycle broker           │
        ├── verification broker        │
        └── apply_patch / shell        │
             │                         │
             ▼                         │
Codex PreToolUse Hook                   │
    └── host-side Policy Gate ◀────────┘
             │
      allow / deny / context
             │
             ▼
 scoped write → isolated proof → completion receipt
```

Setup 결과는 두 trust zone으로 나뉜다.

```text
Project Git tree                         Host user state
────────────────────────────────────    ─────────────────────────────
AGENTS.md managed bridge                trusted hook runtime
.codex/hooks.json                       authoritative gate-state.json
.agent-harness/router.md                setup-status.json
.agent-harness/playbooks/*              proposals and receipts
.agent-harness/repo-profile.json        synchronization locks
.agent-harness/bin/* broker clients
.agent-harness/config.json
.agent-harness/local.md
```

앱 코드를 수정할 수 있는 workspace 안의 파일은 Gate의 authoritative
state가 될 수 없다.

## 컴포넌트

### Setup Skill

사용자가 한 번 호출하는 진입점이다. 기존 파일을 bounded하게 조사하고
변경 계획을 보여준 뒤 정확한 범위에 대해 한 번 승인받는다.

### Repository Profiler

manifest, lockfile, instruction, CI, 알려진 검증 script를 읽어
`repo-profile.json`을 재생성한다. 명령은 탐지할 뿐 Setup 중 실행하지
않는다.

패키지 매니저가 모호하면 npm/pnpm/Yarn/Bun을 추측하지 않는다. 다만
`node --test`처럼 package manager와 무관한 직접 runtime 명령은 shell
조합이 없는 경우에 한해 등록한다.

### Installer

소유권 manifest와 content hash를 사용해 원자적으로 설치한다.

- user-owned: `config.json`, `local.md`, 기존 instruction의 비관리 영역
- installer-owned: bridge, router, Playbook, broker, runtime contract,
  generated profile
- drift가 있으면 조용히 덮어쓰지 않고 `repair` 승인을 요구한다.
- 반복 install은 byte-identical이어야 한다.

### Context Selector와 Read Broker

항상 전체 문서를 넣지 않는다.

1. 얇은 bridge
2. task signal에 맞는 compact context
3. router
4. 필요한 Playbook만
5. 구조 지도
6. 관련 source slice
7. 긴 출력은 모델 밖에서 검색·집계

read broker는 `map`, `search`, `read`, `git-status`, `git-diff`만
허용하고 secret/protected glob, symlink escape, broad dump를 막는다.

### Lifecycle와 Policy Gate

acceptance, Decision, Evidence, Write Lease, verification, completion의
invariant를 host state에서 관리한다. protocol 어휘를 추측하지 않도록
read-only `describe` 인터페이스를 제공한다.

### Verification Broker

Project Profile에 등록된 identifier만 받는다. 정확한 argv로 파싱하고
shell을 사용하지 않는다. Git snapshot, 허용된 runtime, CPU/memory/time
limit, network 차단 안에서 실행한다. live tree를 바꾸거나 input hash가
달라지면 receipt를 발급하지 않는다.

### Benchmark Runtime

control, stable Harness, adaptive-context R&D variant의 trace를 동일 schema로
정규화한다. correctness뿐 아니라 Evidence, 최소 변경, decision safety,
proof, retry/denial/context 비용을 함께 비교한다. synthetic fixture와
provider-attested run을 명확히 구분한다.

## 상태 머신

```text
DISCOVERY_LOCKED
       │ complete structured acceptance
       ▼
   DISCOVERY
    ├── 제품 선택 필요 ─────────────→ DECISION_REQUIRED
    ├── dependency 근거 필요 ───────→ RESEARCH_REQUIRED
    └── 전제 충족 ──────────────────→ READY_TO_WRITE
                                          │ scoped lease
                                          ▼
                                     IMPLEMENTING
                                          │ submitted diff
                                          ▼
                                       VERIFYING
                                     ├─ fail → IMPLEMENTING
                                     └─ proof → COMPLETE
```

공통 결과는 `BLOCKED`와 명시적 `OVERRIDDEN`이다.

중요한 전환 조건:

- 새 사용자 turn은 기존 lease를 폐기하고 Task revision을 올린다.
- unresolved product Decision이 있으면 쓰기 상태로 갈 수 없다.
- dependency Task는 exact version과 native-capability 조사 없이 lease를
  얻을 수 없다.
- protected action 때 base tree, acceptance hash, Evidence hash, allowed
  glob을 다시 확인한다.
- 구현 이후 live output과 receipt의 implementation hash가 달라지면 다시
  검증해야 한다.

## 핵심 도메인 모델

```typescript
interface TaskContract {
  taskId: string;
  revision: number;
  userPromptHash: string;
  outcome: string;
  criteria: AcceptanceCriterion[];
  exclusions: string[];
  assumptions: string[];
  pendingDecisionIds: string[];
}

interface Evidence {
  evidenceId: string;
  kind:
    | "repository-fact"
    | "exact-version"
    | "official-doc"
    | "migration-guide"
    | "type-definition"
    | "source-code"
    | "official-issue"
    | "reproduction"
    | "verification";
  source: string;
  exactVersion?: string;
  contentHash: string;
  capturedAt: string;
}

interface WriteLease {
  leaseId: string;
  taskId: string;
  acceptanceHash: string;
  evidenceSetHash: string;
  baseTreeHash: string;
  allowedGlobs: string[];
  allowedCommands: string[];
}

interface VerificationReceipt {
  verificationId: string;
  commandHash: string;
  outputHash: string;
  exitCode: 0;
  implementationTreeHash: string;
}

interface CompletionReceipt {
  completionId: string;
  taskId: string;
  leaseId: string;
  acceptanceHash: string;
  receiptSetHash: string;
  implementationTreeHash: string;
}
```

## 주요 인터페이스와 이벤트

### Provider events

`UserPromptSubmit`

- 입력: `session_id`, `cwd`, `hook_event_name`, `user_prompt`
- 출력: compact `additionalContext`
- 효과: Task 생성/갱신, 기존 lease 폐기

`PreToolUse`

- 입력: canonical `tool_name`과 provider-native `tool_input`
- `Bash`와 `apply_patch`는 `tool_input.command`를 사용한다.
- 출력: allow, deny reason, 또는 추가 context

공식 Codex 계약상 shell/`exec_command`는 `Bash`, patch는
`apply_patch`다. 수동 replay에서도 이 이름을 바꾸면 유효한 비교가 아니다.

### Project brokers

```text
read_context.py map|search|read|git-status|git-diff
request_write_lease.py describe|set-acceptance|request|approve|renew|complete
run_verification.py list|run <verification-id>
```

정확한 lifecycle token은 `describe` 결과가 authority다. 모델이 enum이나
hash를 추측하거나 brute-force하지 않는다.

## 실패 처리

| 실패 | 동작 |
|---|---|
| project hook이 신뢰되지 않음 | Setup을 `INCOMPLETE`로 유지 |
| write-deny canary가 통과하지 않음 | 완료 가능 상태로 승격하지 않음 |
| malformed provider payload | fail closed |
| protected/secret/symlink 경로 읽기 | broker가 거부 |
| acceptance 또는 Decision 미해결 | write lease 거부 |
| base tree/Evidence/acceptance drift | lease 폐기 또는 갱신 요구 |
| 범위 밖 patch 또는 shell 조합 | PreToolUse에서 거부 |
| 검증 명령 미탐지 | 추측 실행하지 않고 Decision 필요 |
| 격리 기능 없음 | verification proof를 발급하지 않음 |
| test 실패 | `VERIFYING → IMPLEMENTING` |
| 구현자 텍스트만 “완료” | completion receipt 없음 |

## 보안 정책

- `.env*`, private key, credential/token 파일, `.git`, Harness 내부 상태를
  기본 protected glob으로 둔다.
- authoritative state는 project 밖에 두고 권한을 제한한다.
- hook definition hash가 바뀌면 provider에서 다시 신뢰해야 한다.
- shell command는 exact argv와 완전한 command로만 허용한다.
- prefix/suffix, redirect, command substitution, compound shell을 허용하지
  않는다.
- 검증 snapshot에서 network, 외부 secret, 절대 외부 쓰기를 차단한다.
- 외부 문서 내용은 기술 정보일 뿐 Harness 정책을 변경하는 지시가 아니다.
- uninstall과 drift repair는 명시적 승인 없이는 실행하지 않는다.

## 실제 A/B 행동 검증

### 방법

동일한 작은 Git fixture와 동일한 사용자 prompt를 세 arm에 주었다.

- Control: Harness 없음
- Stable: Harness 적용, adaptive task context 끔
- R&D: 같은 Harness, signal 기반 adaptive task context 켬

각 arm은 다른 clean-context agent가 수행했다. Root가 diff, test exit,
Gate state, receipt를 다시 확인했다. 수동 replay에서는 공식 Codex hook
payload를 사용했다.

표 기호:

- `✓`: 관찰된 요구 충족
- `△`: 결과는 있으나 기계적 증거나 효율이 부족
- `✗`: 요구 위반
- `–`: 해당 시나리오에서 비교하지 않음

| 시나리오 / 지표 | Control | Stable | R&D |
|---|---:|---:|---:|
| 라이브러리 버그: 정확한 `2.4.1` 확인 | ✓ | ✓ | ✓ |
| 라이브러리 버그: native option 우선 | ✓ | ✓ | ✓ |
| 라이브러리 버그: 최소 1줄 diff | ✓ | ✓ | ✓ |
| 라이브러리 버그: receipt-backed proof | △ | ✓ | ✓ |
| 모호한 실시간 채팅: 구현 전 결정 질문 | ✗ | ✓ | ✓ |
| 모호한 실시간 채팅: 파일 변경 0 | ✗ | ✓ | ✓ |
| 모호한 실시간 채팅: bounded context 효율 | ✗ | △ | ✓ |
| 초소형 로컬 버그: 정확한 1줄 수정 | ✓ | ✓ | ✓ |
| 초소형 로컬 버그: baseline/final proof | △ | ✓ | ✓ |
| 초소형 로컬 버그: 불필요한 dependency/refactor | ✓ | ✓ | ✓ |

관찰 요약:

- 쉬운 dependency bug에서는 Control도 정답을 냈다. Harness의 차이는
  정답 자체보다 exact-version/native-capability Evidence와 completion
  receipt를 강제한다는 점이었다.
- 모호한 architecture 요청에서 Control은 질문 없이 `ws`를 설치하고
  파일을 바꿨다. Stable과 R&D는 쓰기 전에 멈췄다.
- R&D는 모호한 요청에서 Stable보다 적은 broker read로 더 완전한 질문
  묶음을 만들었다.
- 초소형 버그는 profiler 수정 뒤 Stable과 R&D 모두 동일한 1줄 diff와
  `1/1` test, completion receipt를 만들었다.
- 마지막 untouched R&D 재시험은 acceptance/Proof/검증 순서를 첫 시도에
  맞춰 제품 workflow denial 없이 완료했다. 수동 hook replay가 잘못된
  state 파일을 넣은 1회는 test-driver 오류로 제외했다.

현재 선택은 **adaptive task context를 기본 활성화하되 signal이 있을 때만
추가 context를 주입하는 R&D 방식**이다. 모든 작업에 무거운 절차를
주입하지 않는다.

### A/B에서 발견해 반영한 결함

| 관찰 | 반영한 수정 |
|---|---|
| 같은 prompt의 agent-authored acceptance 초안이 Decision으로 고착 | 동일 provenance의 미승인 초안은 교체 가능하게 함 |
| 첫 검증이 `.pyc`를 만들어 자기 drift 발생 | broker runtime의 bytecode 쓰기 차단 |
| lifecycle enum과 dependency token을 agent가 추측 | read-only `describe`와 정확한 token/hash 반환 |
| 1줄 수정의 indentation drift를 보지 못함 | brokered `git-status`/`git-diff`와 완료 전 diff 확인 |
| 긴 임시 경로에서 task signal이 1,800자 뒤로 잘림 | signal을 path-heavy 안내보다 먼저 배치하고 lifecycle prefix 중복 제거 |
| lockfile 없는 `node --test`가 검증 후보에서 사라짐 | shell-free direct Node test runner를 보수적으로 탐지 |
| thin bridge와 상세 Playbook의 audit 조건 충돌 | audit를 Harness/instruction 변경에만 한정 |
| acceptance 값의 공백/quote 처리에서 불필요한 retry | 한 개의 hyphenated shell token만 쓰도록 주입 문구 명시 |
| criterion이 행동만 말하고 proof와 매핑되지 않음 | 각 criterion token에 등록된 proof kind/ID를 필수로 안내 |
| discovery-locked에서 baseline broker를 먼저 호출 | acceptance/lease 뒤 baseline을 실행하는 순서를 명시 |
| benchmark 표가 부분 run을 완전 비교처럼 보임 | run coverage와 분모를 표에 표시 |

### 제외한 실행

다음은 제품 점수에 넣지 않았다.

- 공식 schema와 다른 hook envelope
- 이전 Harness 파일이 dirty baseline으로 섞인 fixture
- `apply_patch`를 `Bash`로 잘못 표기한 수동 replay
- `gate-state.json` 대신 `setup-status.json`을 넣은 수동 replay
- 중간 도움 메시지를 받은 acceptance 진단 실행
- 로컬 `bubblewrap`/network 환경 때문에 Task 시작 전에 실패한 live CLI

이 구분이 없으면 test-driver 오류를 제품 결함이나 성능으로 잘못 센다.

### 한계

- 각 arm/시나리오가 한 번뿐이라 통계적 유의성이 없다.
- collaboration agent + 수동 hook replay는 실제 Codex provider-attested
  세션과 동일하지 않다.
- 토큰과 wall time이 모든 arm에서 같은 계측기로 수집되지 않았다.
- 따라서 현재 결과는 방향성 있는 smoke evidence이며 자동 promotion
  근거가 아니다.

## 현재 검증

- 전체 Python test suite: `182/182` 통과
- Setup Skill `quick_validate`: 통과
- trusted-hook denial canary와 Harness audit 경로: test suite에서 통과
- 초소형 버그 Stable completion:
  `COMPLETE-59504db31a5656bdafb4`
- 초소형 버그 R&D completion:
  `COMPLETE-30003fd8f5f8d3820f60`
- 최종 untouched R&D completion:
  `COMPLETE-8b73a5e525e011b848e0`

`benchmarks/fixtures/applied-vs-research.jsonl`은 scoring engine용 synthetic
fixture다. 실제 A/B 관찰로 오해하지 않는다.

## 채택한 외부 철학

- [Matt Pocock skills](https://github.com/mattpocock/skills): 한 번 Setup하고
  repo-local skill/instruction을 통해 반복 행동을 자동화하는 UX
- [context-mode](https://github.com/mksglu/context-mode): 큰 출력은 모델
  밖에서 처리하고 파생 결과만 context에 넣기
- [CodeGraph](https://github.com/colbymchenry/codegraph): 파일 전체보다
  구조·관계·영향 범위를 먼저 보기
- [Kage](https://github.com/kage-core/Kage): 기억과 코드 사실에 provenance와
  freshness 붙이기
- [trajectory](https://github.com/letta-ai/trajectory): agent trace를 공통
  schema로 정규화하기
- [harness-engineering](https://github.com/lopopolo/harness-engineering):
  모델 교체 전에 context, tool, permission, verification 환경을 개선하기
- [Codex Hooks 공식 문서](https://learn.chatgpt.com/docs/hooks): provider
  event, canonical tool name, trust, allow/deny 계약

도구 자체를 필수 dependency로 채택한 것이 아니다. 철학을 작은
repo-native broker와 Gate에 구현했다.

## 가장 큰 기술적 위험

가장 큰 위험은 **provider hook이 실제 tool surface를 완전히 관찰한다고
잘못 믿는 것**이다. 공식 문서도 일부 specialized tool path가 기본 hook을
우회할 수 있다고 명시한다. 따라서 provider canary가 통과하지 않으면
Harness를 완료 상태로 보지 않으며, hook만으로 OS sandbox나 사용자 승인
경계를 대체하지 않는다.

두 번째 위험은 process overhead가 작은 작업의 품질 이득보다 커지는
것이다. 그래서 adaptive signal routing, direct verification discovery,
bounded reads, scenario별 A/B를 함께 유지한다.

세 번째 위험은 문서와 runtime 계약의 drift다. installer-owned asset,
content hash, idempotence test, audit, canonical 문서 하나로 이를 줄인다.
