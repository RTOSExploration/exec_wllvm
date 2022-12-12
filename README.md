# exec_wllvm
Intercept syscall execve(arm-none-eabi-gcc) in build systems, then execute wllvm instead

## Usage
`genbc <database> -c BUILD-COMMAND`

E.g.
`genbc ../db -c "cmake --build build -j$(nproc)"`
