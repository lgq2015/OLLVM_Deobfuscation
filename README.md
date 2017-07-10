# OLLVM_Deobfuscation
OLLVM_Deobfuscation 是一款ollvm反混淆工具，目前已经能完美实现x86架构Linux平台下被ollvm混淆过的C/C++代码的反混淆，后续将逐步尝试Android SO文件的反混淆
## 0x01 安装 ##
OLLVM_Deobfuscation依赖以下环境：

- 1)[angr](http://angr.io/): a python framework for analyzing binaries.
- 2)[BARF](https://github.com/programa-stic/barf-project): A multiplatform open source Binary Analysis and Reverse engineering Framework 
- 3)[Z3](https://github.com/Z3Prover/z3): A high-performance theorem prover being developed at Microsoft Research.
- 4)[CVC4](http://cvc4.cs.stanford.edu/web/): An efficient open-source automatic theorem prover for satisfiability modulo theories (SMT) problems.
## 0x02 使用 ##
	$ workon angr
	$ cd path_to_the/barf
	$ python ./src/Deobfuscation.py ./test/target_int_32 0x8048420

## 0x03 Miasm vs OLLVM_Deobfuscation ##
<div align=center><img src="https://github.com/SCUBSRGroup/OLLVM_Deobfuscation/blob/master/test/OLLVM%E5%8F%8D%E6%B7%B7%E6%B7%86%E5%90%8E%E7%9A%84%E6%95%88%E6%9E%9C%E6%88%AA%E5%9B%BE/(%E6%9C%AA%E6%B7%B7%E6%B7%86)target_int_32.png"/></div>\

## 0x04 效果截图 ##