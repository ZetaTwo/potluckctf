#!/bin/env python
import struct
import random
import can
import time

rate = 1

class Heater(can.Listener):

    def __init__(self):
        self.temp = 22.0 # Initialize to room temperature
        self.power = 2000
        self.target = 22

    def _update_temp(self):
        if int(self.temp) > self.target:
            target = self.temp-rate
        elif int(self.temp) < self.target:
            target = self.temp + rate
        else:
            target = self.temp
        self.temp = random.uniform(int(target), int(target)+1)

    def get_temp(self):
        self._update_temp()
        return self.temp

    def get_temp_bytes(self):
        cur = self.get_temp()
        return struct.pack("d", cur) 
    
    def set_target(self, target):
        if target < 22:
            self.target = 22
        self.target = target
        print("Heater Target:", self.target)

    def on_message_received(self, msg):
        self.set_target(int.from_bytes(msg.data))



heater = Heater()
heater.set_target(180)

CAN_EFF_MASK = 0x7FF

def main():
    with can.Bus(interface="socketcan", channel="vcan0", receive_own_messages=True) as bus:
        print_listener = can.Printer()
        bus.set_filters([{
            "can_id": 0x11,
            "can_mask": CAN_EFF_MASK}])
        can.Notifier(bus, [heater])
        while True:
            bus.send(can.Message(arbitration_id=0x12, data=heater.get_temp_bytes()))
            print("Sent Message")
            time.sleep(1)


if __name__ == "__main__":
    main()

