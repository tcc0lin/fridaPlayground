import json
import frida
from pprint import pprint as print

TARGET_PKG_NAME = "com.tencent.wework"
TARGET_NAME = "企业微信"
log_file = open("wework_network.log", "w+")


def on_message(message, data):
    write_data = {
        "so_name": message["payload"]["so_name"],
        "func": message["payload"]["func"],
        "data": data.hex(),
    }
    log_file.write(json.dumps(write_data) + "\n")
    log_file.flush()


def load_script(session):
    with open("_agent.js", "r") as f:
        script = session.create_script(f.read())
        script.on("message", on_message)
        script.load()
        return script


def run(run_mode: str):
    if run_mode == "attach":
        session = frida.get_usb_device().attach(TARGET_NAME)
        script = load_script(session)
    elif run_mode == "spawn":
        device = frida.get_usb_device()
        pid = device.spawn([TARGET_PKG_NAME])
        session = device.attach(pid)
        script = load_script(session)
        device.resume(pid)
    script.post({"type": "run_mode", "payload": run_mode})
    input()


run("spawn")
