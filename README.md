# OLLVM_Deobfuscation
OLLVM_Deobfuscation 是一款[OLLVM](https://github.com/obfuscator-llvm/obfuscator/tree/llvm-3.6.1)反混淆工具，目前已经能完美实现x86架构Linux平台下被ollvm混淆过的C/C++代码的反混淆，后续将逐步尝试Android SO文件的反混淆
## 0x01 安装 ##
OLLVM_Deobfuscation依赖以下环境：
- 1)[angr](http://angr.io/): a python framework for analyzing binaries.
- 2)[BARF](https://github.com/programa-stic/barf-project): A multiplatform open source Binary Analysis and Reverse engineering Framework 
- 3)[Z3](https://github.com/Z3Prover/z3): A high-performance theorem prover being developed at Microsoft Research.
- 4)[CVC4](http://cvc4.cs.stanford.edu/web/): An efficient open-source automatic theorem prover for satisfiability modulo theories (SMT) problems.
## 0x02 使用 ##
我们就以工程test文件下，经OLLVM平坦化混淆后的target_int_32_flat做反混淆测试用例，执行以下命令进行反混淆

	$ workon angr
	$ cd path_to_the/barf
	$ python ./src/Deobfuscation.py ./test/target_int_32_flat 0x8048420

## 0x03 Miasm vs OLLVM_Deobfuscation ##
### What is Miasm ###
[Miasm](https://github.com/cea-sec/miasm)是一款基于Python的逆向框架，自身具备符号执行引擎和IR中间语言语义解析功能，能解析PE / ELF 32等多种格式，并支持X86 / ARM / MIPS / SH4 / MSP430等多种平台
#### 原理功能 ####
Miasm和OLLVM_Deobfuscation的详细对比如下：
<div align=center><img src="https://github.com/SCUBSRGroup/OLLVM_Deobfuscation/blob/master/Miasm%20vs%20OLLVM_Deobfuscation/Miasm%20vs%20OLLVM_Deobfuscation.png"/></div>

#### 效果截图 ####
分别使用Miasm和OLLVM_Deobfuscation对target_int_32_flat进行反混淆，其反混淆效果截图如下所示：

(a)未混淆                                        (b)OLLVM平坦化混淆后
<figure class="half">
	<a href="https://github.com/SCUBSRGroup/OLLVM_Deobfuscation/blob/master/Miasm%20vs%20OLLVM_Deobfuscation/target_int_32.png"><img src="https://github.com/SCUBSRGroup/OLLVM_Deobfuscation/blob/master/Miasm%20vs%20OLLVM_Deobfuscation/target_int_32.png" width="400" title="(a)未混淆" /></a>
	<a href="https://github.com/SCUBSRGroup/OLLVM_Deobfuscation/blob/master/Miasm%20vs%20OLLVM_Deobfuscation/target_int_32_flat.png"><img src="https://github.com/SCUBSRGroup/OLLVM_Deobfuscation/blob/master/Miasm%20vs%20OLLVM_Deobfuscation/target_int_32_flat.png" width="400" title="(b)OLLVM平坦化混淆后" /></a></p>		
</figure>
                       
<center><img src="https://github.com/SCUBSRGroup/OLLVM_Deobfuscation/blob/master/Miasm%20vs%20OLLVM_Deobfuscation/Miasm%20Deobfuscation%20.png" title="(c)Miasm反混淆效果截图"/></center>
<center><font color=grey>** (c)Miasm反混淆效果截图 **</font></center>

<figure class="half">
	<a href="https://github.com/SCUBSRGroup/OLLVM_Deobfuscation/blob/master/Miasm%20vs%20OLLVM_Deobfuscation/OLLVM_Deobfuscation%20Screenshots/j_x_jump_target_int_32_flat.recovered.png"><img src="https://github.com/SCUBSRGroup/OLLVM_Deobfuscation/blob/master/Miasm%20vs%20OLLVM_Deobfuscation/OLLVM_Deobfuscation%20Screenshots/j_x_jump_target_int_32_flat.recovered.png" width="400" title="(d)OLLVM_Deobfuscation(j_x_jump)反混淆效果截图" /></a>
	<a href="https://github.com/SCUBSRGroup/OLLVM_Deobfuscation/blob/master/Miasm%20vs%20OLLVM_Deobfuscation/OLLVM_Deobfuscation%20Screenshots/jnz_jump_target_int_32_flat.recovered.png"><img src="https://github.com/SCUBSRGroup/OLLVM_Deobfuscation/blob/master/Miasm%20vs%20OLLVM_Deobfuscation/OLLVM_Deobfuscation%20Screenshots/jnz_jump_target_int_32_flat.recovered.png" title="(e)OLLVM_Deobfuscation(jnz_jump)反混淆效果截图"/></a></p>	
</figure>	

<img src="https://github.com/SCUBSRGroup/OLLVM_Deobfuscation/blob/master/Miasm%20vs%20OLLVM_Deobfuscation/OLLVM_Deobfuscation%20Screenshots/OLLVM_Deobfuscation%E5%8F%8D%E6%B7%B7%E6%B7%86%E5%90%8E%E7%9A%84%E6%96%87%E4%BB%B6%E8%BF%90%E8%A1%8C%E6%95%88%E6%9E%9C%E6%88%AA%E5%9B%BE.png" title="(f)OLLVM_Deobfuscation反混淆文件运行截图"/>
<center><font color=grey>** (f)OLLVM_Deobfuscation反混淆文件运行截图 **</font></center>
