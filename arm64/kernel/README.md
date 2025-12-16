## toy_kernel: XNU-style arm64 kernel pwn (easy)

Игрушечное "ядро" под `arm64`/`arm64e`, которое имитирует типичный XNU‑кейс:

- kernel‑heap, управляемый через `kobject`'ы;
- баг с refcount / UAF (release не чистит слот);
- infoleak структуры, где видно `encoded_handler`;
- "защита" function pointer'а через `handler ^ cookie`, как примитивная PAC/obfuscation;
- отдельные user‑контролируемые аллокации того же размера (`raw_alloc`) для heap‑spray и reclaim freed chunk'а.

### Сборка

```sh
cd kernel
make
```

Бинарь `toy_kernel` не PIE, без stack protector — запускай его через уже привычный раннер, например:

```sh
cd kernel
../buf_ov/main ./toy_kernel
```

### Интерфейс (как "системные вызовы")

- `create kobject` — аллоцирует `kobject` + kernel‑буфер, ставит handler = `safe_handler ^ cookie`, печатает слот и адрес.
- `retain kobject` — увеличивает refcount.
- `release kobject` — уменьшает refcount и при `0` делает `free`, **но не обнуляет слот** → классический UAF.
- `write kobject data` — пишет данные в kernel‑буфер.
- `debug leak kobject` — сыро дампит всю структуру `kobject` (в том числе `encoded_handler`).
- `raw alloc` — аллоцирует кусок `sizeof(kobject)` и даёт записать туда байты (heap‑spray / fake kobject).
- `raw free` — освобождает такой кусок.
- `invoke kobject handler` — декодирует `encoded_handler ^ cookie` и вызывает полученный function pointer.

### Намёк на эксплуатацию

1. Создаешь `kobject`, дампишь его через `debug leak`.
2. По логу видишь `encoded_handler`, а из баннера знаешь `safe_handler` → вычисляешь `cookie`.
3. Делаешь `release` → `kobject` освобождён, но слот всё ещё хранит dangling pointer.
4. Через `raw alloc` спреем аллокации размера `sizeof(kobject)` до тех пор, пока один из них не попадёт на адрес UAF‑объекта, и пишем туда фейковую структуру, где:
   - `encoded_handler = (uintptr_t)win ^ cookie`.
5. Вызываешь `invoke kobject handler` на UAF‑слоте → прыжок в `win()` в "kernel"‑контексте.

Дальше можешь тренировать ROP под arm64, усложнять модель heap'а или добавлять свои баги поверх этой основы.

---

## hard_kernel: userclient / cred / UAF (harder)

`hard_kernel` — более приближенный к XNU сценарий:

- есть `userclient` с полями:
  - `kaddr` — "kernel" адрес;
  - `ksize` — размер региона;
  - `backing` — честный буфер для данных;
- глобальные `kcred`:
  - `g_cred` (текущие права, uid=1000);
  - `g_root_cred` (uid=0, gid=0, как эталон root);
- цель — добиться `g_cred.uid == 0`, тогда `check_root_and_win()` дернёт `win()` и выдаст shell.

### Сборка

```sh
cd kernel
make          # соберёт toy_kernel и hard_kernel
```

Запускать можно через твой раннер:

```sh
cd kernel
../buf_ov/main ./hard_kernel
```

### Интерфейс hard_kernel

- `1) open userclient`
  - аллоцирует `userclient` + `backing` буфер;
  - выставляет `kaddr = backing`, `ksize = size`;
  - печатает адреса, id, размер.
- `2) write client backing buffer`
  - пишет данные в честный буфер, ничего особо интересного.
- `3) close userclient (UAF bug)`
  - делает `free(backing)` и `free(uc)`, **но не чистит указатель в g_clients[]** → UAF на `userclient`.
- `4) debug dump client`
  - дампит поля `userclient` по слоту (адрес, `kaddr`, `ksize`, `backing`).
- `5) kernel write via client (buggy bounds)`
  - использует `uc->kaddr` как kernel‑адрес;
  - спрашивает `off` и `sz`, читает до 0x400 байт и делает `memcpy(uc->kaddr + off, buf, sz)`;
  - **BUG**: проверяет только `off <= ksize`, но не `off + sz <= ksize`;
  - если `userclient` честный — это просто кривой bounds, если fake — превращается в произвольную запись по адресу `kaddr + off`.
- `6) raw alloc`
  - аллоцирует чанк `sizeof(userclient)` и даёт записать в него **полностью контролируемые байты**;
  - печатает адрес — нужен для heap feng shui / UAF reclaim.
- `7) raw free`
  - освобождает такой чанк.
- `8) check root & win()`
  - выводит `g_cred.uid/gid`;
  - если `uid == 0` — вызывает `win()` (shell).

### Намёк на эксплуатацию hard_kernel

1. Открываешь один `userclient` (опция 1), запоминаешь адрес `uc`.
2. Закрываешь его (опция 3) → UAF: `g_clients[slot]` всё ещё указывает на freed `userclient`.
3. Через `raw alloc` (опция 6) аллоцируешь `sizeof(userclient)`‑чанки, пока какой‑то из них не получит **тот же адрес**, что и freed `uc` (смотри лог адресов).
4. В этот чанк пишешь **фейковую структуру userclient**, в которой:
   - поле `kaddr` = `(char *)&g_cred` (адрес есть в баннере `debug_info()` при старте);
   - `ksize` достаточно большой (например, `0x100`), чтобы проверки проходили;
   - остальное можно забить мусором.
5. Теперь слот с UAF `userclient` на самом деле указывает на твой fake `userclient` из raw‑чанка.
6. Вызываешь `5) kernel write via client` на этом слоте, выбираешь:
   - `off = 0` (или точное смещение до `uid` внутри `kcred`, если хочешь красиво);
   - `sz = 8` и подаёшь 8 байт `0x00` (или копию `g_root_cred` и т.п.).
   → Получается записать нужные байты поверх `g_cred.uid`/`gid`.
7. Дальше `8) check root & win()`:
   - если `g_cred.uid == 0` — попадаешь в `win()` и получаешь shell.

Это уже больше похоже на реальный XNU‑кейc:

- есть UAF на объекте ядра (`userclient`);
- через heap feng‑shui/RAW‑аллокации захватываешь его чанк;
- строишь **fake объект**, на который ссылаются все дальнейшие "системные вызовы";
- превращаешь это в произвольную запись по произвольному kernel‑адресу;
- меняешь cred и через отдельный privileged‑путь получаешь `win()`.

