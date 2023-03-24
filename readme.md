# trace_tool

用于黑盒测试中计算路径覆盖率。首先需要先对带执行程序patch
```
Usage: tracer_tool patch [OPTIONS] <ELF> <DB>

Arguments:
  <ELF>  File to be patched
  <DB>   Patch DB file

Options:
      --r2 <R2>  r2 command [default: r2]
  -h, --help     Print help

```

对一个文件夹的所有可执行程序和so批量patch可以用下面命令
```bash
find /usr/lib/office6/ -type f -and \( -name "*.so" -or -name "*.so.*" -or -perm 0111 \) -print0 | xargs -0 -I {} trace_tool patch {} ./db.json
```
patch后可以用run命令执行patch后的程序，程序运行结束后就会输出路径覆盖率
```bash
Usage: tracer_tool run [OPTIONS] <DB> [CMD]...

Arguments:
  <DB>      Patch DB file
  [CMD]...  Command to run

Options:
  -o, --output <OUTPUT>  Save result to file(json format)
  -h, --help             Print help
```