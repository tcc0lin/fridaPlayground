import json
import frida
import struct
from pprint import pprint as print


def on_message(message, data):
    print(message)
    print(data)


def load_script(session):
    with open("_agent.js", "r") as f:
        script = session.create_script(f.read())
        script.on("message", on_message)
        script.load()
        return script


# choose run_mode
run_mode = "attach"
if run_mode == "attach":
    session = frida.get_usb_device().attach("企业微信")
    script = load_script(session)
elif run_mode == "spawn":
    device = frida.get_usb_device()
    pid = device.spawn(["com.tencent.wework"])
    session = device.attach(pid)
    script = load_script(session)
    device.resume(pid)
script.post({"type": "run_mode", "payload": run_mode})
input()
