import asyncio
import logging
import argparse

from glasgow.applet import GlasgowAppletError
from glasgow.applet.interface.uart import UARTApplet
from glasgow.target.hardware import GlasgowHardwareTarget
from glasgow.device.hardware import GlasgowHardwareDevice
from glasgow.access.direct import DirectMultiplexer, DirectDemultiplexer, DirectArguments

logger = logging.getLogger(__loader__.name)

async def _main():
    device = GlasgowHardwareDevice()
    await device.reset_alert("AB")
    await device.poll_alert()
    await device.set_voltage("AB", 3.3)
    target = GlasgowHardwareTarget(revision=device.revision,
                                    multiplexer_cls=DirectMultiplexer,
                                    with_analyzer=False)
    access_args = DirectArguments(applet_name="uart",
                                    default_port="AB",
                                    pin_count=16)
    uart0_parser = argparse.ArgumentParser('uart0')
    uart1_parser = argparse.ArgumentParser('uart1')
    UARTApplet.add_build_arguments(uart0_parser, access_args)
    UARTApplet.add_build_arguments(uart1_parser, access_args)
    UARTApplet.add_run_arguments(uart0_parser, access_args)
    UARTApplet.add_run_arguments(uart1_parser, access_args)
    UARTApplet.add_interact_arguments(uart0_parser)
    UARTApplet.add_interact_arguments(uart1_parser)

    uart0_args = uart0_parser.parse_args(["-V", "3.3", "--port", "A", "-b", "115200", "--pulls", "socket", "tcp:localhost:13371"])
    uart1_args = uart0_parser.parse_args(["-V", "3.3", "--port", "B", "-b", "115200", "--pulls", "socket", "tcp:localhost:13372"])
    uart0 = UARTApplet()
    uart1 = UARTApplet()
    uart0.build(target, uart0_args)
    uart1.build(target, uart1_args)
    plan = target.build_plan()
    await device.download_target(plan)
    device.demultiplexer = DirectDemultiplexer(device, target.multiplexer.pipe_count)

    async def run_applet(uart: UARTApplet, args):
        try:
            iface = await uart.run(device, args)
            return await uart.interact(device, args, iface)
        except GlasgowAppletError as e:
            uart.logger.error(str(e))
            return 1
        except asyncio.CancelledError:
            return 130 # 128 + SIGINT
        finally:
            await device.demultiplexer.flush()
            device.demultiplexer.statistics()

    tasks = [
        asyncio.ensure_future(run_applet(uart0, uart0_args)),
        asyncio.ensure_future(run_applet(uart1, uart1_args))
    ]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)

def main():
    root_logger = logging.getLogger()
    term_handler = logging.StreamHandler()
    root_logger.addHandler(term_handler)

    loop = asyncio.get_event_loop()
    exit(loop.run_until_complete(_main()))

if __name__ == "__main__":
    main()