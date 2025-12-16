# writeup wrote chatgpt based on my solution and the source code file

# Raiser – exploit writeup

## English

### Files
- `raiser` – 64-bit PIE binary.
- `libc.so.6`, `ld-linux-x86-64.so.2` – glibc and loader used by the binary.
- `e.py` – exploit script written with pwntools.

### Challenge
The binary implements a simple calculator that repeatedly asks for a base and a power, computes `base^power` using 64‑bit integers, and prints the result.  
For a special input value (`base == 1337`) it reveals a hidden “History feature” that prints one value from an internal history buffer.

The goal is to obtain code execution (a shell) using only interaction with the program, in spite of enabled mitigations (PIE, NX, no stack canary, partial RELRO).

### Vulnerabilities
- The history buffer is an array of 16 `unsigned long long` values on the stack, cleared at the start of `main`.
- After each calculation, the program stores the last result into this history via a global counter `cnt`, but never checks that `cnt < 16`. After enough operations, writes go past the end of the array and start overwriting the stack frame, including the saved return address.
- The hidden “History feature” is triggered when `base == 1337`. Instead of performing an exponentiation, the program prints `history[power]` using `%llu` without checking that `power` is within `[0, 15]`.
- Because the history array lives on the stack, an out‑of‑bounds read with a chosen index leaks stack values, including the saved return address into `libc`, which gives a libc address.

### Exploit idea
1. Trigger the hidden feature with `base = 1337` and `power = 19` so that the program prints the saved return address from the stack. Subtracting a known offset (`0x28150`) yields the libc base address.
2. From this base, compute absolute addresses of:
   - a `ret` gadget (for stack alignment),
   - a `pop rdi; ret` gadget,
   - the `/bin/sh` string in libc,
   - the `system` function.
3. Perform many harmless calculations (`base = 1, power = 1`) to increment `cnt` and fill the history array until writes reach the stack frame area near the saved return address.
4. Use four more calculations where the base is set to the computed gadget/function addresses and the power is `1`. These writes place the ROP chain on the stack:
   - overwritten saved return address → `ret` gadget,
   - next slot → `pop rdi; ret`,
   - next slot → address of `/bin/sh`,
   - next slot → address of `system`.
5. Finally, send a calculation with a very large power (`power > 0x1000`, for example `5000`). This triggers the `"Not supported..."` branch, after which `main` returns and the process immediately executes the ROP chain, resulting in `system("/bin/sh")` and an interactive shell.

All of these steps are automated in `e.py`.

### How to run
- Install dependencies: `pip install pwntools`.
- Make sure `raiser`, `libc.so.6`, `ld-linux-x86-64.so.2` and `e.py` are in the same directory.
- Run the exploit locally:

  ```bash
  python3 e.py
  ```

  For debugging, you can start it under GDB:

  ```bash
  python3 e.py GDB
  ```

  The `start()` helper in `e.py` takes care of invoking GDB with the provided `gdbscript`.

---

## Русский

### Файлы
- `raiser` — 64‑битный PIE‑бинарник.
- `libc.so.6`, `ld-linux-x86-64.so.2` — используемая glibc и загрузчик.
- `e.py` — эксплойт на базе библиотеки pwntools.

### Описание задачи
Бинарник реализует простой калькулятор степеней: в цикле он спрашивает «Enter base:» и «Enter power:», вычисляет `base^power` в 64‑битной арифметике и печатает результат.  
Для специального значения `base = 1337` появляется скрытая «History feature», которая выводит одно значение из внутренней истории вычислений.

Цель задачи — получить выполнение произвольного кода (получить shell), взаимодействуя только через стандартный ввод/вывод, несмотря на включённые защиты (PIE, NX, отсутствие canary, частичный RELRO).

### Уязвимости
- История результатов хранится в массиве из 16 элементов `unsigned long long` на стеке, который обнуляется в начале `main`.
- После каждого вычисления программа кладёт последний результат в эту историю, используя глобальный счётчик `cnt` как индекс, но нигде не проверяет, что `cnt < 16`. В итоге при достаточном количестве операций записи выходят за пределы массива и начинают затирать стековый фрейм, включая сохранённый адрес возврата.
- Скрытая функция истории активируется при `base = 1337`. Вместо возведения в степень программа берёт `history[power]` и печатает его через `%llu`, вообще не проверяя, что значение `power` попадает в допустимый диапазон `[0, 15]`.
- Так как история расположена на стеке, выход за границы массива позволяет по управляемому индексу читать произвольные значения со стека, в том числе сохранённый адрес возврата в `libc`, что даёт утечку адреса libc.

### Идея эксплойта
1. Активировать скрытую историю с параметрами `base = 1337` и `power = 19`, чтобы программа вывела сохранённый адрес возврата со стека. Вычитая известное смещение (`0x28150`), получаем базовый адрес libc.
2. По базовому адресу libc вычислить:
   - гаджет `ret` (для выравнивания стека),
   - гаджет `pop rdi; ret`,
   - адрес строки `/bin/sh` в libc,
   - адрес функции `system`.
3. Выполнить множество безопасных вычислений с параметрами `base = 1`, `power = 1`, чтобы увеличить `cnt` и заполнить массив истории до тех пор, пока записи не начнут попадать в область стекового фрейма рядом с сохранённым адресом возврата.
4. Затем четырьмя дополнительными вычислениями, где `base` — это заранее посчитанные адреса гаджетов/функций, а `power = 1`, записать на стек ROP‑цепочку:
   - переписанный адрес возврата → гаджет `ret`,
   - следующий слот → `pop rdi; ret`,
   - далее → адрес строки `/bin/sh`,
   - далее → адрес `system`.
5. В конце отправить вычисление с очень большим показателем степени (`power > 0x1000`, например `5000`). Это переводит программу в ветку `"Not supported..."`, после чего `main` возвращается, управление передаётся на переписанный адрес возврата, и исполняется наша ROP‑цепочка, вызывающая `system("/bin/sh")` и выдающая интерактивный shell.

Все эти шаги реализованы в скрипте `e.py`.

### Запуск эксплойта
- Установить зависимости: `pip install pwntools`.
- Положить `raiser`, `libc.so.6`, `ld-linux-x86-64.so.2` и `e.py` в один каталог.
- Запустить эксплойт локально:

  ```bash
  python3 e.py
  ```

- Для отладки под GDB:

  ```bash
  python3 e.py GDB
  ```

  Функция `start()` в `e.py` сама правильно запускает бинарник под GDB с нужным скриптом.

