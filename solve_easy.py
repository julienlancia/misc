# -*- coding: utf-8 -*-
import angr
import claripy
import logging
import sys


def hook_any(state):
    import ipdb;ipdb.set_trace()

def hook_bypass(state):
    pass

def hook_memcpy(state):
        string = ""
        for i in range(60):
            string +=  chr(state.mem[state.regs.r3+i].uint8_t.concrete)
        print(string)

class ret0(angr.SimProcedure):
    def run(self):
            return 0



# logging.getLogger('angr').setLevel('DEBUG')
# logging.getLogger('angr.manager').setLevel(logging.DEBUG)
#logging.getLogger("angr.engines.unicorn").setLevel('DEBUG')
#logging.getLogger("angr.engines.vex").setLevel('DEBUG')
# logging.getLogger("angr.engines").setLevel('DEBUG')
# logging.getLogger("angr.state_plugins.unicorn_engine").setLevel('DEBUG')

p = angr.Project("vault")


# p.hook(0x400ad6, hook_bypass, 4)
p.hook(0x4007d0, ret0())

##### SYMBOLIC ARGS 

# BUF_LEN = 64
# flag = claripy.BVS('flag', BUF_LEN*8)
# argv = [p.filename, flag]

# state = p.factory.full_init_state(args=argv, add_options=angr.options.unicorn, remove_options={angr.options.LAZY_SOLVES})
# state = p.factory.full_init_state(args=argv, add_options=angr.options.unicorn)


##### SYMBOLIC STDIN 

# BUF_LEN = 128
# flag = claripy.BVS('flag', BUF_LEN*8)
# state = p.factory.entry_state(stdin=flag, add_options=angr.options.unicorn)
state = p.factory.entry_state()

##### ADD CONSTRAINTS TO FLAG

# WARNING : no line feed !!!
def constraint_char(state, c):
    '''returns constraints s.t. c is printable'''
    return state.solver.And(c <= '~', c >= ' ')

# flag_val = "ECSC{"
# cpt = 0
# for i, c in enumerate(flag.chop(8)):
#     if(i < len(flag_val)):
#         val = flag_val[i]
#         state.add_constraints(c == val)
#     else:
#         state.add_constraints(char(state, c))

#####

#sm = p.factory.simgr(state, save_unconstrained=True)
# sm = p.factory.simgr(state, veritesting=True)
sm = p.factory.simgr(state)

# base = 0x400000


def print_instr(sm):
    print(sm.active)
    state = sm.active[-1]
    block = p.factory.block(state.addr)
    block.pp()
    #raw_input()
    return sm


def print_active(sm):
    #print sm.active
    print("%d active states"%len(sm.active))
    if len(sm.active)>0:
        s = sm.active[-1]
        print(s)
    return sm

# sm.run()
# res=sm.run(step_func=print_active)

# TRICK TO GET A SOLUTION WHEN COMPLEXITY IS HIGH : DEpth First
# sm.use_technique(angr.exploration_techniques.DFS())

# Not working anymore
#sm.use_technique(angr.exploration_techniques.LoopLimiter())



res=sm.explore(find=0x00400be7, avoid=[0x00400baf,0x00400b84] , step_func=print_active)



# # CONTEXT
# res=sm.explore(find=0xA95+base, avoid=0xAA8+base, step_func=print_active)




if len(sm.found)>0:
    found = sm.found[0] # A state that reached the find condition from explore
    flag = found.posix.dumps(1)
    # flag = found.solver.eval(sym_arg, cast_to=str) # Return a concrete string value for the sym arg to reach this state
    print(flag)
    # print(flag.encode("hex"))
else:
    print("state Not found")
    print(sm.deadended)
    # import ipdb;ipdb.set_trace()
