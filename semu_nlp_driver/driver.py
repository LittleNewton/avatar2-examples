import sys
sys.path.insert(0,'../')

from avatar2 import *
from avatar2.peripherals import AvatarPeripheral

from os.path import abspath
from time import sleep

from capstone import *
from capstone.arm  import *

import threading
import subprocess
import os
import logging

from avatar2.message import RemoteInterruptEnterMessage
from avatar2.message import RemoteInterruptExitMessage

from avatar2 import TargetStates

from threading import Thread, Event
from utils import *

# Configure the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# proj specific settings
sample = 'frdmk66f_uart_polling.axf'
# sample = 'frdmk66f_uart_polling.bin'
#sample = '../MK64F-unit_tests/NUTTX-USART.elf'
OUT_DIR = "./myavatar"
fn = '../../projs/infoExtraction/k64.txt'
QEMU_PATH = "../../avatar2/targets/build/qemu/arm-softmmu/qemu-system-arm"

# Read board config from a file.
# TO-DO: I'm curious about this file!!
regs, data_register, allTAs, counters, interrupt_freq = read_file(fn)

# Create avatar instance with custom output directory
avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)
avatar.load_plugin('arm.armv7m_interrupts')

# Add qemu target
print("[+] Creating the QEMUTarget")
qemu = avatar.add_target(QemuTarget,
                            gdb_executable="arm-none-eabi-gdb",
                            gdb_port=4321,
                            firmware=sample, cpu_model="cortex-m4",
                            entry_address=0x1020D,
                            executable=QEMU_PATH,
                            log_items = ['avatar','in_asm','nochain'])

#ROM = bytearray()
class Interrupter(Thread):
    host = None  # The host to be interrupted. MUST SET AT RUNTIME
    def __init__(self, irq_num):
        self.irq_num = irq_num
        self.irq_enabled = Event()
        self.irq_enabled.clear()
        self.started = Event()
        self._shutdown = Event()
        Thread.__init__(self)

    def run(self):
        self.started.set()
        if not qemu:
            raise RuntimeError("Must set host first")
        while not self._shutdown.is_set():
            while not self._shutdown.is_set() and self.irq_enabled.is_set() and qemu.state == TargetStates.RUNNING:
                qemu.protocols.interrupts.inject_interrupt(self.irq_num)
                self.irq_enabled.clear()

class NLPPeripheral(AvatarPeripheral):
    def hw_read(self, offset, size, pc):
        """
        Read: return the value.
        """
        logger.info("+++++++++++++++++++++++++++++++++")
        logger.info("[+] QEMU reached peripheral: read")
        
        # Get the physical address in ARM memory space.
        phaddr = self.address + offset
        logger.info("[+] Read: " + self.name + ", at: " + format(phaddr, '#04x') + "(" + format(offset, '#04x') + "), size: " + format(size, '#04x') + ", pc: " + format(pc, '#04x'))
        CountDown(regs, counters)
        
        # If this register is a DataRegister, then return the r (reserved?) value.
        if phaddr in data_register:
            res = regs[phaddr].r_value
            hardware_write_to_receive_buffer(regs, phaddr, 0xA, 32)
        else:
            res = regs[phaddr].cur_value
        UpdateGraph(regs, data_register, allTAs, interrupt_freq, READ, phaddr, qemu)
        
        if type(res) == int:
            logger.info("return value from NLP = " + format(res, '#04x'))
        else:
            logger.info("return value from NLP = " + res)
        return res

    def hw_write(self, offset, size, value, pc):
        """
        Write: Return successfully or unsuccessfull of writing. So the returned value is a boolean one.
        """
        logger.info("+++++++++++++++++++++++++++++++++")
        logger.info("[+] QEMU reached peripheral: write")
        phaddr = self.address + offset
        logger.info("[+] Write: " + self.name + " at: " + format(phaddr, '#04x') + "(" + format(offset, '#04x') + "), size: " + format(size, '#04x') + ", value: " + format(value, '#04x') + ", pc: " + format(pc, '#04x'))
        if phaddr not in data_register:
            regs[phaddr].cur_value = value
        else:
            regs[phaddr].t_value = value
        UpdateGraph(regs, data_register, allTAs, interrupt_freq, WRITE, phaddr, qemu)
        return True

    def __init__(self, name, address, size, **kwargs):
        AvatarPeripheral.__init__(self, name, address, size)
        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
        #self.regs = kwargs['kwargs']['regs']
        #self.data_register = kwargs['kwargs']['data_register']
        #self.allTAs = kwargs['kwargs']['allTAs']
        #self.interrupt_freq = kwargs['kwargs']['interrupt_freq']
        #self.host = kwargs['kwargs']['host']
        #UpdateGraph(regs, data_register, allTAs, interrupt_freq, WRITE, 0, qemu)
        logger.info("avatar peripheral successfully intalled!!")
    
    

class OtherPeripheral(AvatarPeripheral):

    def hw_read(self, offset, size, pc):
        logger.info("+++++++++++++++++++++++++++++++++")
        logger.info("[+] QEMU reached peripheral: read")
        logger.info("[+] Read: " + self.name + ", at: " + format(self.address + offset, '#04x') +
                     "(" + format(offset, '#04x') + "), size: " + format(size, '#04x') +
                     ", pc: " + format(pc, '#04x'))

        return 0x0

    def nop_write(self, offset, size, value, pc):
        logger.info("+++++++++++++++++++++++++++++++++")
        logger.info("[+] QEMU reached peripheral: write")
        logger.info("[+] Write: " + self.name + " at: " + format(self.address + offset, '#04x') +
                     "(" + format(offset, '#04x') + "), size: " + format(size, '#04x') +
                     ", value: " + format(value, '#04x') + ", pc: " + format(pc, '#04x'))

        return True

    def __init__(self, name, address, size, **kwargs):
        AvatarPeripheral.__init__(self, name, address, size)
        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.nop_write
        #logger.info("avatar peripheral successfully intalled!!")


def exit_callback(avatar, *args, **kwargs):
    interrupt_freq[num] = 0
    pass

if __name__ == "__main__":

    # add memory
    ram  = avatar.add_memory_range(0x1fff0000, 0x50000, name='ram',
                                   permissions='rw-')
    rom  = avatar.add_memory_range(0x0, 0x2000000, name='rom',
                                   file=sample,
                                   permissions='r-x')

    #OtherPeripheralList = {
    #        "watchdog": (0x40052000, 0x100),
    #        }
    #for name, addr in OtherPeripheralList.items():
    #    avatar.add_memory_range(addr[0], addr[1], name=name, emulate=OtherPeripheral, permissions='rw-')

    NLPPeripheralList = {
            "uart": (0x40000000, 0x20000000),
            }
    
    #model_kwargs = {'filename': fn, 'host': qemu, 
    #                'regs':regs, 'data_register':data_register, 
    #                'allTAs':allTAs, 'counters':counters, 
    #                'interrupt_freq':interrupt_freq, 'serial':True}
    for name, addr in NLPPeripheralList.items():
        avatar.add_memory_range(addr[0], addr[1], name=name, emulate=NLPPeripheral, permissions='rw-')#, kwargs=model_kwargs)
    

    #set_QEMU()
    logger.info("[+] Initializing the targets")
    avatar.init_targets()
    
    logger.info("[+] Running in QEMU until a peripherial is accessed")

    qemu.regs.sp = 0x20030000
    qemu.bp(0x10e8e)
    qemu.bp(0x110e0)

    #qemu.protocols.interrupts.enable_interrupts()
    #qemu.protocols.interrupts.inject_interrupt(irq_num)
    #exit
    #avatar.watchmen.add_watchmen('RemoteInterruptExit', 'after', exit_callback)

    qemu.cont()# Continue execution
    qemu.wait()# Before doing anything else, wait for the breakpoint to be hit



    while True:
        pass
