import angr

project = angr.Project("./encr.bin", auto_load_libs=False)
state = project.factory.full_init_state(add_options=angr.options.unicorn)
sm = p.factory.simulation_manager(state)

# simgr = project.factory.simgr()
# simgr.run(until=lambda sm_: len(sm_.active) > 1)

# print(simgr.found)
# if (len(simgr.found) > 0):
#     for found in simgr.found:
#         ans = found.posix.dumps(0)
#         print(f"Password is: {ans}")
