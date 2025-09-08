네, `tmux`의 훌륭한 대안인 `screen` 사용법에 대해 알려드릴게요. `screen`은 `tmux`보다 더 오래되었고, 대부분의 유닉스 계열 시스템에 기본적으로 설치되어 있어 가볍게 사용하기 좋습니다.

`tmux`의 세션, 윈도우, 팬(pane) 개념과 유사하지만 용어가 조금 다릅니다. `screen`의 핵심은 모든 명령어가 **`Ctrl + a`** 라는 **'명령 키(Prefix)'** 로 시작한다는 점입니다. `tmux`의 `Ctrl + b`와 같은 역할이죠.

-----

### \#\# 🚀 `screen` 핵심 사용법

`screen`의 기본적인 흐름은 **'세션을 만들고(create), 잠시 빠져나왔다가(detach), 다시 접속하는(attach)'** 것입니다.

#### \#\#\# 1. 세션 (Session) 관리

세션은 작업을 관리하는 가장 큰 단위입니다.

  * **새 세션 시작**:

    ```shell
    screen
    ```

      * 이름을 지정하여 세션 시작 (**권장**):
        ```shell
        screen -S [세션이름]
        ```
        예: `screen -S web_server`

  * **세션 목록 확인**: 현재 실행 중인 모든 `screen` 세션을 보여줍니다.

    ```shell
    screen -ls
    ```

  * **세션에서 잠시 빠져나오기 (Detach)**: 현재 작업을 백그라운드에서 계속 실행시키고 터미널만 빠져나옵니다.

      * `Ctrl + a`를 누른 후 `d` 키를 누르세요.

  * **세션에 다시 접속하기 (Attach/Resume)**: Detach 했던 세션으로 다시 돌아갑니다.

      * 세션이 하나일 때:
        ```shell
        screen -r
        ```
      * 세션이 여러 개일 때 (세션 이름이나 PID로 접속):
        ```shell
        screen -r [세션이름 또는 PID]
        ```
        예: `screen -r web_server`

  * **세션 완전히 종료하기**: 세션 안에서 `exit` 명령어를 입력하거나, 단축키를 사용합니다.

      * `exit`
      * `Ctrl + a`를 누른 후 `k` 키를 누르세요. (현재 창을 강제로 종료)

-----

### \#\# 💻 창 (Window) 및 화면 분할 (Split) 관리

`tmux`의 윈도우(window)와 팬(pane)처럼 `screen`도 하나의 세션 안에서 여러 개의 창을 만들고 화면을 분할할 수 있습니다.

#### \#\#\# 1. 창 (Window) 관리

  * **새 창 만들기**: `Ctrl + a`를 누른 후 `c` 키
  * **다음 창으로 이동**: `Ctrl + a`를 누른 후 `n` 키
  * **이전 창으로 이동**: `Ctrl +a`를 누른 후 `p` 키
  * **특정 번호의 창으로 이동**: `Ctrl + a`를 누른 후 `0-9` 숫자 키
  * **창 목록 보기**: `Ctrl + a`를 누른 후 `w` 키

#### \#\#\# 2. 화면 분할 (Split / Region)

`tmux`의 pane과 같은 기능입니다.

  * **수평으로 화면 분할**: `Ctrl + a`를 누른 후 `Shift + s` (대문자 S)
  * **수직으로 화면 분할**: `Ctrl + a`를 누른 후 `|` (파이프 문자)
  * **분할된 화면 간 이동**: `Ctrl + a`를 누른 후 `Tab` 키
  * **현재 분할된 화면 닫기**: `Ctrl + a`를 누른 후 `Shift + x` (대문자 X)
  * **현재 화면 제외하고 모두 닫기**: `Ctrl + a`를 누른 후 `Shift + q` (대문자 Q)

-----

### \#\# ✨ `tmux` 사용자를 위한 빠른 비교표

| 기능 (Function) | `screen` 명령어 | `tmux` 명령어 |
| :--- | :--- | :--- |
| **명령 키 (Prefix)** | **`Ctrl + a`** | **`Ctrl + b`** |
| 새 이름 지정 세션 시작 | `screen -S <name>` | `tmux new -s <name>` |
| 세션 목록 보기 | `screen -ls` | `tmux ls` |
| 세션 나가기 (Detach) | `Ctrl + a, d` | `Ctrl + b, d` |
| 세션 재접속 (Attach) | `screen -r <name>` | `tmux a -t <name>` |
| 새 창 만들기 (Window) | `Ctrl + a, c` | `Ctrl + b, c` |
| 다음 창으로 이동 | `Ctrl + a, n` | `Ctrl + b, n` |
| 창 목록 보기 | `Ctrl + a, w` | `Ctrl + b, w` |
| 수평 화면 분할 | `Ctrl + a, S` | `Ctrl + b, "` |
| 수직 화면 분할 | `Ctrl + a, \|` | `Ctrl + b, %` |
| 분할 화면 간 이동 | `Ctrl + a, Tab` | `Ctrl + b, <방향키>` |
| 분할 화면 닫기 | `Ctrl + a, X` | `Ctrl + b, x` |

`screen`은 기본 기능에 충실하여 매우 가볍고 빠르다는 장점이 있습니다. 복잡한 설정 없이 바로 사용하고 싶을 때 훌륭한 선택이 될 수 있습니다.

