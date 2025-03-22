import { fpcore } from "../../core/FPCore";
import { CallbackModel } from "../../modules/Model";
import { hook_methods_by_class } from "../../utils/method_helper";
import { hook_tls13_hkdf_expand } from "../../modules/ssl/hook_ssl";
import { hook_exports } from "../../utils/so_helper";
let wework_network_lib = "libwework_framework.so";

function callback_for_python(so_name: string) {
  return (_ctx: InvocationContext, model: CallbackModel) => {
    send(
      {
        so_name: so_name,
        func: model.getFunction(),
      },
      model.getData()
    );
  };
}

function attach() {
  // fpcore.libc.hook_socket();
  // fpcore.ssl.hook_ssl_data(
  //   wework_network_lib,
  //   callback_for_python(wework_network_lib)
  // );
  // fpcore.ssl.hook_ssl_cipher(
  //   wework_network_lib,
  //   callback_for_python(wework_network_lib)
  // );
  // fpcore.ssl.hook_socket_stream();
  // console.log(22);
  hook_tls13_hkdf_expand(wework_network_lib);
  // hook_exports(wework_network_lib, ["hkdf"]);
}

function main() {
  attach();
}

function spawn() {
  fpcore.linker.hook_dlopen(wework_network_lib, () => {
    main();
  });
}
export function entry() {
  // run by frida
  // main();
  // run by python
  recv("run_mode", (obj) => {
    let run_mode = obj.payload;
    console.log(run_mode);
    switch (run_mode) {
      case "attach":
        attach();
        break;
      case "spawn":
        spawn();
        break;
    }
  });
}
