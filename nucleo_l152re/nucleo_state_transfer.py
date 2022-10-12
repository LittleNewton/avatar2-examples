from os.path import abspath
from time import sleep

import os

# import pdb

from avatar2 import *

# set env var
os.environ['AVATAR2_PANDA_EXECUTABLE'] = "panda-system-arm"

# Change to control whether the state transfer should be explicit or implicit
USE_ORCHESTRATION = 0


def obvious_print(s):
    print("=========" + s + "=========")


def main():

    # Configure the location of various files
    firmware = abspath('./firmware.bin')

    openocd_config = abspath('./nucleo-l152re.cfg')

    # Initiate the avatar-object
    avatar = Avatar(arch=ARM_CORTEX_M3, output_directory='/tmp/avatar')

    # Create the target-objects
    nucleo = avatar.add_target(OpenOCDTarget, openocd_script=openocd_config)

    qemu = avatar.add_target(PandaTarget, gdb_port=1236)

    # Define the various memory ranges and store references to them
    rom = avatar.add_memory_range(0x08000000, 0x1000000, file=firmware)
    ram = avatar.add_memory_range(0x20000000, 0x14000)
    mmio = avatar.add_memory_range(
        0x40000000, 0x1000000, forwarded=True, forwarded_to=nucleo)

    # Initialize the targets
    avatar.init_targets()
    obvious_print("Avatar Inited")

    if not USE_ORCHESTRATION:
        # This branch shows explicit state transferring using avatar

        # 1) Set the breakpoint on the physical device and execute up to there
        nucleo.set_breakpoint(0x8005104)
        nucleo.cont()
        nucleo.wait()

        # 2) Transfer the state from the physical device to the emulator
        obvious_print("Now the state is transfering")
        avatar.transfer_state(nucleo, qemu, synced_ranges=[ram])

        print("State transfer finished, emulator $cpsr is: 0x%x" % qemu.regs.cpsr)

        print("State transfer finished, emulator $pc is: 0x%x" % qemu.regs.pc)
    else:
        # This shows implicit state transferring using the orchestration plugin

        # 1) Load the plugin
        avatar.load_plugin('orchestrator')

        # 2) Specify the first target of the analysis
        avatar.start_target = nucleo

        # 3) Configure transitions
        #    Here, only one transition is defined. Note that 'stop=True' forces
        #    the orchestration to stop once the transition has occurred.
        avatar.add_transition(0x8005104, nucleo, qemu,
                              synced_ranges=[ram], stop=True)

        # 4) Start the orchestration!
        obvious_print("Now we are trying to start orchestration")
        avatar.start_orchestration()
        obvious_print("Now start orchestration")

        print("State transfer finished, emulator $pc is: 0x%x" % qemu.regs.pc)

    # Continue execution in the emulator.
    # Due due to the forwarded mmio, output on the serial port of the physical
    # device (/dev/ttyACMx) can be observed, although solely the emulator
    # is executing.
    qemu.cont()

    # Further analysis could go here:
    # import IPython; IPython.embed()
    qemu.stop()
    obvious_print("Qemu Stoped")

    # Let this example run for a bit before shutting down avatar cleanly
    sleep(5)
    avatar.shutdown()


if __name__ == '__main__':
    main()
    obvious_print("RUN done.")
