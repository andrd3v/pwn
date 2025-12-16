```
       start() execution
       +--------------+
       |   bl main()  | --> store the return address to LR
       +--------------+

<addr     main() stack
       +---------------+
       |     [FP+8]    | <-- initially created at [SP-8]
       |    X30 (LR)   | <-- LR for start()
       +---------------+
       |     [FP+0]    | <-- initially created at [SP-16]
       |    X29 (FP)   | <-- FP for start()
FP --> +---------------+
       |     [FP-4]    |
       |     buf[0]    | <-- oldest
       +---------------+
       |      ...      |
       +---------------+
       |     [FP-n]    |
       |     buf[n]    |
       +---------------+
SP --> |      ...      | <-- alignment space, SP decrements once a new stack element is added
       +---------------+
>addr
       main() execution
       +---------------+
       |   bl vuln()   | --> store the return address to LR
       +---------------+     (LR for start() is still in the stack)
```
