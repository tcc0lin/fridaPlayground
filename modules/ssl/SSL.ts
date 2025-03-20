import { CallbackModel } from "../Model";
import {
  hook_ssl_write,
  hook_ssl_read,
  hook_bio_write,
  hook_evp_cipherupdate,
  hook_evp_encryptupdate,
  hook_evp_decryptupdate,
  hook_aes_set_encrypt_key,
  hook_aes_cbc_encrypt,
  hook_crypto_cbc128_encrypt,
} from "./hook_ssl";
import { hook_socket_stream } from "./hook_ssl_java";
export class SSL {
  public hook_ssl_data(
    so_name: string = "libssl.so",
    callback: (ctx: InvocationContext, model: CallbackModel) => void = () => {}
  ): void {
    hook_ssl_write(so_name, callback);
    hook_ssl_read(so_name, callback);
    hook_bio_write(so_name);
  }
  public hook_ssl_cipher(
    so_name: string = "libssl.so",
    callback: (ctx: InvocationContext, model: CallbackModel) => void = () => {}
  ): void {
    hook_evp_cipherupdate(so_name);
    hook_evp_encryptupdate(so_name, callback);
    hook_evp_decryptupdate(so_name, callback);
    hook_aes_set_encrypt_key(so_name, callback);
    hook_aes_cbc_encrypt(so_name);
    hook_crypto_cbc128_encrypt(so_name);
  }
  public hook_socket_stream() {
    hook_socket_stream();
  }
}
