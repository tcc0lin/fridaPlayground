import { fpcore } from "../../core/FPCore";
import { CallbackModel } from "../../modules/Model";
import { hook_exports } from "../../utils/sohelper";

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
export function entry() {
  let wework_network_lib = "libwework_framework.so";
  let system_ssl_lib = "libssl.so";

  // fpcore.libc.hook_socket();

  // fpcore.ssl.hook_ssl_data(
  //   wework_network_lib,
  //   callback_for_python(wework_network_lib)
  // );
  // fpcore.ssl.hook_ssl_cipher(
  //   wework_network_lib,
  //   callback_for_python(wework_network_lib)
  // );

  // fpcore.ssl.hook_ssl(system_ssl_lib);
  // fpcore.ssl.hook_bio(system_ssl_lib);

  fpcore.linker.hook_dlopen(wework_network_lib, () => {
    console.log("caonim");
  });

  // test
  // const filters: string[] = ["EVP"];
  // hook_exports(wework_network_lib, filters);
}
