# !/usr/bin/python
# coding=utf-8

# Imports from Miasm framework

from miasm2.core.bin_stream                 import bin_stream_str

from miasm2.arch.x86.disasm                 import dis_x86_32

from miasm2.arch.x86.ira                    import ir_a_x86_32

from miasm2.arch.x86.regs                   import all_regs_ids, all_regs_ids_init

from miasm2.ir.symbexec                     import symbexec

from miasm2.expression.simplifications      import expr_simp

from miasm2.expression.expression 			import ExprInt, ExprCond ,ExprInt32, ExprId

from miasm2.expression.modint 				import int32

import miasm2.expression.expression as m2_expr
# Binary path and offset of the target function 【程序路径与目标函数代码偏移】

offset = 0x59b
block_state = stack = []
dump_id = dump_mem = []

filename = "/home/hack/Android/OLLVM/OLLVM_TEST/flat_test/target_flat"
#filename = "/home/hack/Android/OLLVM/OLLVM_TEST/flat_test/target_flat"
# Get Miasm's binary stream [获取文件二进制流]

bin_file = open(filename, "rb").read() # fix: (此处原文代码BUG，未指定“rb”模式可能导致文件读取错误)

bin_stream = bin_stream_str(bin_file)
# Disassemble blocks of the function at 'offset' 【反汇编目标函数基本块】

mdis = dis_x86_32(bin_stream)     #mdis= machine 反编译引擎, 形如：<miasm2.arch.x86.disasm.dis_x86_32 object at 0xb668258c>

disasm = mdis.dis_multibloc(offset) #（disasm即所有的基本块的汇编代码）从offset起，反汇编每个可达基本块，并返回AsmCFG实例(已反汇编的基本块的)
# Create target IR object and add all basic blocks to it 【创建IR对象并添加所有的基本块】

ir = ir_a_x86_32(mdis.symbol_pool)

for bbl in disasm: 
	#print "------------bbl=",bbl
	ir.add_bloc(bbl) #将native block 添加到当前IR中

#print "+++++++++++++++++ir=",ir
# Init our symbols with all architecture known registers 【符号初始化】

symbols_init =  {}

for i, r in enumerate(all_regs_ids):

    symbols_init[r] = all_regs_ids_init[i]

#print "!!!!!!!!!!!!!!!!!!!symbols_init=",symbols_init
# Create symbolic execution engine 【创建符号执行引擎】

symb = symbexec(ir, symbols_init)
'''Get the block we want and emulate it 【获取目标代码块并进行符号执行】
   We obtain the address of the next block to execute '''
#print "!!!!!!!!!!!!!!!!!!!symb=",symb


#======================================单个地址计算
block = ir.get_bloc(offset)#
print '+'*120

nxt_addr = symb.emulbloc(block) #对irbloc 实例进行符号执行,返回下一跳转offset地址条件表达式

#block_state = str(symb.dump_id())+str(symb.dump_mem()) # symb.dump_id()为<type 'NoneType'>
#print block_state 

simp_addr = expr_simp(nxt_addr)  #上述代码只是针对单个基本块进行符号执行 ##
'''运用简化表达式，找到稳定的状态，返回一个精简的Expr instance (expr_simp = expression_simplify)
   The simp_addr variable is an integer expression (next basic block offset) 【如果simp_addr变量是整形表达式(即下一个基本块的偏移)】
''' 
print type(simp_addr)  
if isinstance(simp_addr,ExprInt):
	print "Jump on next basic block: %s" % simp_addr 
 
elif isinstance(simp_addr, ExprCond):  # The simp_addr variable is a condition expression 【如果simp_addr变量为条件表达式】
	branch1 = simp_addr.src1
	branch2 = simp_addr.src2
	print("Condition: %s or %s" % (branch1,branch2))
	print type(branch2)





		


	