#!usr/bin/python
#coding=utf-8
from barf.barf import BARF
import angr    #负责分析+协调：主要用到了Project/Factory/Path
import simuvex #负责程序状态+模拟符号执行：SimuVEX提供了对给定机器状态下给定的VEX IR块的一个语义的解析（在条件跳转的情况下，产生几个机器状态）
               #SimuVEX是VEX IR的模拟引擎。 给定VEX IRSB和初始状态（内存和寄存器），它可以执行静态，动态或符号分析。
import pyvex   #二进制-->VEX IR转换：PyVEX提供了将二进制代码转换为VEX中间表示（IR）的接口
import claripy 
import struct
import sys
import os

def get_retn_predispatcher(cfg):
    global main_dispatcher
    for block in cfg.basic_blocks:
        if len(block.branches) == 0 and block.direct_branch == None:
            retn = block.start_address
        elif block.direct_branch == main_dispatcher:
            pre_dispatcher = block.start_address
    return retn, pre_dispatcher
    
def get_relevant_nop_blocks(cfg):
    global pre_dispatcher, prologue, retn
    relevant_blocks = []
    nop_blocks = []
    for block in cfg.basic_blocks:
        if block.direct_branch == pre_dispatcher and len(block.instrs) > 2: #使用更严格的相关基本块筛选规则
            relevant_blocks.append(block.start_address)
        elif block.start_address != prologue and block.start_address != retn:
            nop_blocks.append(block)
    return relevant_blocks, nop_blocks

def statement_inspect(state):#inspenct在遇到类型为ITE的IR表达式时，改变临时变量的判断值，执行2次以获取分支地址
    global modify_value
    expressions = state.scratch.irsb.statements[state.inspect.statement].expressions#irsb=IR基本块,expressions : [<pyvex.expr.ITE object at 0x7f02cbacbe10>, <pyvex.expr.RdTmp object at 0x7f02cb998dd0>, <pyvex.expr.Const object at 0x7f02cb99a320>, <pyvex.expr.Const object at 0x7f02cb99a248>]
    if len(expressions) != 0 and isinstance(expressions[0], pyvex.expr.ITE):#如果expressions[0]为 ITE条件表达式，表示有cmov分支（ITE=if-then-else）
        state.scratch.temps[expressions[0].cond.tmp] = modify_value #modify_value: <BV1 1> 或者modify_value: <BV1 0>
        state.inspect._breakpoints['statement'] = [] #设置breakpoint为 IR statement被解析处

def symbolic_execution(start_addr, hook_addr=None, modify=None, inspect=False):
    global b, relevants, modify_value
    if hook_addr != None: #存在call指令，hook_addr是call指令的地址
        b.hook(hook_addr, retn_procedure, length=5)#b = angr.Project(filename），执行hook时默认跳过5个字节

    if modify != None:
        modify_value = modify
    state = b.factory.blank_state(addr=start_addr, remove_options={simuvex.o.LAZY_SOLVES})#获取在函数执行开始时的空白状态，禁用延迟求解器LAZY_SOLVES
    if inspect:
        state.inspect.b('statement', when=simuvex.BP_BEFORE, action=statement_inspect)#监视出现ITE条件表达式的断点，事件statement的BP_BEFORE属性，在statement执行前就断下来
    p = b.factory.path(state)#path表征程序执行时的基本块序列

    p.step() #返回可能的执行路径列表successors后继状态 p.successors[0]

    #-------------------dse 0x804859c---------------------
    #================================================================================
    #p: <Path with 0 runs (at 0x804859c : /home/hack/angr_env/OLLVM/barf/0/target_int_32_flat3.6)>
    #p.successors[0]: <Path with 1 runs (at 0x804869e : /home/hack/angr_env/OLLVM/barf/0/target_int_32_flat3.6)>
    #p.successors[0].addr: 0x804869e

    while p.successors[0].addr not in relevants: #如果下一跳地址不在真实块中，继续符号执行，直到获得真实块地址（因为modify的值<BV1 1>确定了eax/ecx的值，从而能确定起点-->终点路径）
        p = p.successors[0]
        p.step()
    return p.successors[0].addr#返回符号执行终点的基本块首地址

def retn_procedure(state):#遇到call指令，使用hook的方式直接返回 
    global b
    ip = state.se.any_int(state.regs.ip) #获取ip 寄存器中的地址
    b.unhook(ip) #angr.Project.unhook()移除 hook
    return

#*******************symbolic execution*********************
#-------------------dse 0x8048813---------------------
#b_hook: <angr.project.Project object at 0x7f8f4e884590>
#================================================================================
#ip: 0x804881c  call指令所在行地址
#b_unhook: <angr.project.Project object at 0x7f8f4e884590>

#-------------------dse 0x804883f---------------------
#b_hook: <angr.project.Project object at 0x7f8f4e884590>
#================================================================================
#ip: 0x8048848
#b_unhook: <angr.project.Project object at 0x7f8f4e884590>


def fill_nop(data, start, end):#start,end 都是采用的offset偏移地址
    global opcode
    for i in range(start, end):
        data[i] = opcode['nop']

def fill_jmp_offset(data, start, offset):
    jmp_offset = struct.pack('<i', offset)
    for i in range(4):
        data[start + i] = jmp_offset[i]

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print 'Usage: python deflat.py filename function_address(hex)'
        exit(0)
    opcode = {'a':'\x87', 'ae': '\x83', 'b':'\x82', 'be':'\x86', 'c':'\x82', 'e':'\x84', 'z':'\x84', 'g':'\x8F', 
              'ge':'\x8D', 'l':'\x8C', 'le':'\x8E', 'na':'\x86', 'nae':'\x82', 'nb':'\x83', 'nbe':'\x87', 'nc':'\x83',
              'ne':'\x85', 'ng':'\x8E', 'nge':'\x8C', 'nl':'\x8D', 'nle':'\x8F', 'no':'\x81', 'np':'\x8B', 'ns':'\x89',
              'nz':'\x85', 'o':'\x80', 'p':'\x8A', 'pe':'\x8A', 'po':'\x8B', 's':'\x88', 'nop':'\x90', 'jmp':'\xE9', 'j':'\x0F'}
    filename = sys.argv[1]
    start = int(sys.argv[2], 16)
    barf = BARF(filename)
    base_addr = barf.binary.entry_point >> 12 << 12  #base_addr = 0x8048000
    b = angr.Project(filename, load_options={'auto_load_libs': False, 'main_opts':{'custom_base_addr': 0}})#<angr.project.Project object at 0x7fcec726d5d0>
    cfg = barf.recover_cfg(ea_start=start)#cfg: <barf.analysis.basicblock.basicblock.ControlFlowGraph object at 0x7fddab480fd0>
    cfg.save("target_cfg", print_ir=True, format='dot')
    blocks = cfg.basic_blocks#blocks: [<barf.analysis.basicblock.basicblock.BasicBlock object at 0x7fddab4192d0>,..]
    #获取相应的基本块地址
    prologue = start
    main_dispatcher = cfg.find_basic_block(prologue).direct_branch
    retn, pre_dispatcher = get_retn_predispatcher(cfg)
    relevant_blocks, nop_blocks = get_relevant_nop_blocks(cfg)
    print '*******************relevant blocks************************'
    print 'prologue:%#x' % start
    print 'main_dispatcher:%#x' % main_dispatcher
    print 'pre_dispatcher:%#x' % pre_dispatcher
    print 'retn:%#x' % retn
    print 'relevant_blocks:', [hex(addr) for addr in relevant_blocks] #基本块列表relevant_blocks: ['0x804859c', '0x80485ba',..]

    print '*******************symbolic execution*********************'
    relevants = relevant_blocks
    relevants.append(prologue)
    relevants_without_retn = list(relevants)
    relevants.append(retn)# relevants为所有真实块地址列表（包含返回块）
    flow = {}
    for parent in relevants:
        flow[parent] = [] #flow={0x804859c: [], 0x80485ba: [],..}
                          #parent为字典的键，其后为相应的键对应的value
    modify_value = None
    patch_instrs = {}
    
    for relevant in relevants_without_retn:
        print '-------------------dse %#x---------------------' % relevant
        block = cfg.find_basic_block(relevant)
        has_branches = False
        hook_addr = None
        for ins in block.instrs: #ins:基本块中每一条指令对应一个指令对象<barf.core.reil.reil.DualInstruction object at 0x7f87defa8368>

            if ins.asm_instr.mnemonic.startswith('cmov'):#cmov所在的块就是跳转条件判断块
                patch_instrs[relevant] = ins.asm_instr
                has_branches = True
            elif ins.asm_instr.mnemonic.startswith('call'):
                hook_addr = ins.address #hook_addr是call指令的地址

        #patch_instrs统计cmov跳转条件指令对应的指令对象实体
        #patch_instrs={0x804861c: <barf.arch.x86.x86base.X86Instruction object at 0x7fd67c36d738>, 
        #0x804859c: <barf.arch.x86.x86base.X86Instruction object at 0x7fd67c2e56d0>, 
        #0x80485dd: <barf.arch.x86.x86base.X86Instruction object at 0x7fd67c307ae0>}

        if has_branches:
            flow[relevant].append(symbolic_execution(relevant, hook_addr, claripy.BVV(1, 1), True)) #BVV =BitVector Value，位向量值=memory, registers, and temps（临时变量）中的值
            flow[relevant].append(symbolic_execution(relevant, hook_addr, claripy.BVV(0, 1), True))
        else:
            flow[relevant].append(symbolic_execution(relevant, hook_addr))
     
    print '************************flow******************************'
    for (k, v) in flow.items():
        print '%#x:' % k, [hex(child) for child in v]

    print '************************patch*****************************'#patch二进制程序
    flow.pop(retn)
    origin = open(filename, 'rb')
    origin_data = list(origin.read())
    origin.close()
    recovery = open(filename + '.recovered', 'w+')
    for nop_block in nop_blocks:
        fill_nop(origin_data, nop_block.start_address - base_addr, nop_block.end_address - base_addr + 1) 

    for (parent, childs) in flow.items():
        if len(childs) == 1:#直接跳转块,把最后一条指令改成jmp指令跳转到下一真实块 
            last_instr = cfg.find_basic_block(parent).instrs[-1].asm_instr
            file_offset = last_instr.address - base_addr
            origin_data[file_offset] = opcode['jmp']
            file_offset += 1#跳转至下一基本块，为无用块
            fill_nop(origin_data, file_offset, file_offset + last_instr.size - 1)
            fill_jmp_offset(origin_data, file_offset, childs[0] - last_instr.address - 5)

        

        else:
            instr = patch_instrs[parent] #cmov判断分支指令所在行
            file_offset = instr.address - base_addr #cmov指令offset
            fill_nop(origin_data, file_offset, cfg.find_basic_block(parent).end_address - base_addr + 1)#nop掉从CMOV指令开始的以后汇编指令，并在其后添加jmp指令
            
            origin_data[file_offset] = opcode['j']

            origin_data[file_offset + 1] = opcode[instr.mnemonic[4:]] 

            fill_jmp_offset(origin_data, file_offset + 2, childs[0] - instr.address - 6)

            file_offset += 6
            origin_data[file_offset] = opcode['jmp']
            fill_jmp_offset(origin_data, file_offset + 1, childs[1] - (instr.address + 6) - 5)

    recovery.write(''.join(origin_data))
    recovery.close()
    print 'You got it! The recovered file: %s' % (filename + '.recovered')



































































































































