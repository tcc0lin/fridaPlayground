import { fpcore } from "../../core/FPCore";
import { CallbackModel } from "../../modules/Model";
import { hook_exports } from "../../utils/sohelper";

let wework_network_lib = "libwework_framework.so";

function callback_for_python(so_name: string) {
  return (model: CallbackModel) => {
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

  fpcore.ssl.hook_ssl_data(
    wework_network_lib,
    callback_for_python(wework_network_lib)
  );
  fpcore.ssl.hook_ssl_cipher(
    wework_network_lib,
    callback_for_python(wework_network_lib)
  );

  // fpcore.ssl.hook_ssl();
  // fpcore.ssl.hook_bio();

  // test
  // const filters: string[] = ["EVP"];
  // hook_exports(wework_network_lib, filters);
}

function spawn() {
  fpcore.linker.hook_dlopen(wework_network_lib, () => {
    attach();
  });
}
export function entry() {
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
