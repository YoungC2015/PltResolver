# PltResolver
A plugin to resolve `.plt.sec` symbols in IDA.

## Installation
Move `PltResolver_plugin.py` into `%IDA%/plugins/`.

## Usage

**Only tested on IDA 7.5 with python 3.8.**

**Can only used for i386 and amd64 arch elf binary.**
Press `Ctrl+Shift+J` or `Edit->Parse .plt.sec symbols`.

## Screenshot

- Before:

![](assets/before.png)

![](assets/before2.png)

- After:

![](assets/after.png)

![](assets/after2.png)