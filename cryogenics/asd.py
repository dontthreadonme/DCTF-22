import angr
import claripy
import time


def symbolic_execution():
    # addresses and buffer size obtained with angr-management
    # success should represent the address of the "win" condition that angr is seeking to reach
    success = 0x4001ea  # adr of puts("You won")

    # fail should be an adress or optionally a list of addresses
    # whenever one of these addresses is reached angr drops the current simulation so no resources are wasted in further exploring these paths
    flag_length = 15

    proj = angr.Project("./cryogenics",  auto_load_libs=False)

    # creating the symbolic bit vector, each element of it representing a character of the password that can take any value
    flag_chars = [claripy.BVS(f'{i}', 8) for i in range(flag_length)]
    flag = claripy.Concat(*flag_chars)

    # initialising the state and providing the right channel for the input
    state = proj.factory.full_init_state(
        args=['./cryogenics'],
        add_options=angr.options.unicorn,
        stdin=flag
    )

    # adding constraints assuming each char in the password is a printable ASCII character
    for k in flag_chars:
        state.solver.add(k >= 1)
        state.solver.add(k <= 127)

    # our_string = "XS"

    # for i, c in enumerate(our_string):
    #     state.solver.add(flag_chars[1] != c)
    #     state.solver.add(flag_chars[0] != c)


    # starting the simulation and instructing angr on which states to explore or to avoid
    # more details: https://docs.angr.io/core-concepts/pathgroups#simple-exploration
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=success)

    # if an input that reaches the success target was found then it is printed to the console
    print(simgr.found)
    if (len(simgr.found) > 0):
        for found in simgr.found:
            ans = found.posix.dumps(0)
            print(f"Password is: {ans}")


if __name__ == "__main__":
    before = time.time()
    symbolic_execution()
    after = time.time()
    print(f"Time elapsed: {after-before:.3g} seconds")
