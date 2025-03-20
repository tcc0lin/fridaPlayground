import { CallbackModel } from "../Model";
export function hook_ssl_write(
  so_name: string,
  callback: (ctx: InvocationContext, model: CallbackModel) => void = () => {}
) {
  var SSL_write_ptr = Module.getExportByName(so_name, "SSL_write");
  let prefix = `[ ${so_name} ]`;
  Interceptor.attach(SSL_write_ptr, {
    onEnter: function (args) {
      this.ssl = args[0].toString();
      this.buf = args[1];
      this.size = args[2].toInt32();
      let func_info = `onEnter SSL_write { size: ${
        this.size
      } size_hex: 0x${this.size.toString(16)} }\n`;
      console.log(prefix, func_info, this.buf.readByteArray(this.size));
      // callback
      let model = new CallbackModel();
      model.setFunction("SSL_write");
      model.setData(this.buf.readByteArray(this.size));
      callback(this, model);
    },
    onLeave: function (retval) {},
  });
}

export function hook_ssl_read(
  so_name: string,
  callback: (tx: InvocationContext, model: CallbackModel) => void = () => {}
) {
  var SSL_read_ptr = Module.getExportByName(so_name, "SSL_read");
  let prefix = `[ ${so_name} ]`;
  Interceptor.attach(SSL_read_ptr, {
    onEnter: function (args) {
      this.ssl = args[0].toString();
      this.buf = args[1];
    },
    onLeave: function (retval) {
      const len = retval.toInt32();
      if (len < 0) {
        return;
      }
      let func_info = `onEnter SSL_read { size: ${len} size_hex: 0x${len.toString(
        16
      )} }\n`;
      console.log(prefix, func_info, this.buf.readByteArray(len));
      // callback
      let model = new CallbackModel();
      model.setFunction("SSL_read");
      model.setData(this.buf.readByteArray(len));
      callback(this, model);
    },
  });
}

export function hook_bio_write(so_name: string) {
  var bio_write_ptr = Module.getExportByName(so_name, "BIO_write");
  let prefix = `[ ${so_name} ]`;
  Interceptor.attach(bio_write_ptr, {
    onEnter: function (args) {
      this.bio = args[0];
      this.dataPtr = args[1];
      this.len = args[2].toInt32();
      let func_info = `onEnter BIO_write { size: ${
        this.len
      } size_hex: 0x${this.len.toString(16)} }\n`;
      console.log(prefix, func_info, this.dataPtr.readByteArray(this.len));
    },
    onLeave: function (retval) {},
  });
}

export function hook_evp_cipherupdate(so_name: string) {
  let prefix = `[ ${so_name} ]`;
  var EVP_CipherUpdate_ptr = Module.getExportByName(
    so_name,
    "EVP_CipherUpdate"
  );
  // EVP_CipherUpdate
  // int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
  //   const unsigned char *in, int inl)
  Interceptor.attach(EVP_CipherUpdate_ptr, {
    onEnter: function (args) {
      this.out = args[1];
      this.outl = args[2];
      this.in = args[3];
      this.inl = args[4].toInt32();
      let func_info = `onEnter EVP_CipherUpdate { mode: ${args[0]
        .add(0x10)
        .readInt()} size: ${this.inl} size_hex: 0x${this.inl.toString(16)} }\n`;
      console.log(prefix, func_info, this.in.readByteArray(this.inl));
    },
    onLeave: function (retval) {
      if (this.outl == null) {
        return;
      }
      this.outl = this.outl.readInt();
      let func_info = `onLeave EVP_CipherUpdate { size: ${
        this.outl
      } size_hex: 0x${this.outl.toString(16)} }\n`;
      console.log(prefix, func_info, this.out.readByteArray(this.outl));
    },
  });
}
export function hook_evp_encryptupdate(
  so_name: string,
  callback: (ctx: InvocationContext, model: CallbackModel) => void = () => {}
) {
  let prefix = `[ ${so_name} ]`;
  var EVP_EncryptUpdate_ptr = Module.getExportByName(
    so_name,
    "EVP_EncryptUpdate"
  );
  // EVP_EncryptUpdate
  Interceptor.attach(EVP_EncryptUpdate_ptr, {
    onEnter: function (args) {
      this.out = args[1];
      this.outl = args[2];
      this.in = args[3];
      this.inl = args[4].toInt32();
      let func_info = `onEnter EVP_EncryptUpdate { size: ${
        this.inl
      } size_hex: 0x${this.inl.toString(16)} }\n`;
      console.log(prefix, func_info, this.in.readByteArray(this.inl));
      // callback
      let model = new CallbackModel();
      model.setFunction("EVP_EncryptUpdate");
      model.setData(this.in.readByteArray(this.inl));
      callback(this, model);
    },
    onLeave: function (retval) {
      if (this.outl == null) {
        return;
      }
      this.outl = this.outl.readInt();
      let func_info = `onLeave EVP_EncryptUpdate { size: ${
        this.outl
      } size_hex: 0x${this.outl.toString(16)} }\n`;
      console.log(prefix, func_info, this.out.readByteArray(this.outl));
    },
  });
}
export function hook_evp_decryptupdate(
  so_name: string,
  callback: (ctx: InvocationContext, model: CallbackModel) => void = () => {}
) {
  let prefix = `[ ${so_name} ]`;
  var EVP_DecryptUpdate_ptr = Module.getExportByName(
    so_name,
    "EVP_DecryptUpdate"
  );
  // EVP_DecryptUpdate
  // int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
  //   const unsigned char *in, int inl)
  Interceptor.attach(EVP_DecryptUpdate_ptr, {
    onEnter: function (args) {
      this.out = args[1];
      this.outl = args[2];
      this.in = args[3];
      this.inl = args[4].toInt32();
      let func_info = `onEnter EVP_DecryptUpdate { size: ${
        this.inl
      } size_hex: 0x${this.inl.toString(16)} }\n`;
      console.log(prefix, func_info, this.in.readByteArray(this.inl));
    },
    onLeave: function (retval) {
      if (this.outl == null) {
        return;
      }
      this.outl = this.outl.readInt();
      let func_info = `onLeave EVP_DecryptUpdate { size: ${
        this.outl
      } size_hex: 0x${this.outl.toString(16)} }\n`;
      console.log(prefix, func_info, this.out.readByteArray(this.outl));
      // callback
      let model = new CallbackModel();
      model.setFunction("EVP_DecryptUpdate");
      model.setData(this.out.readByteArray(this.outl));
      callback(this, model);
    },
  });
}
export function hook_aes_set_encrypt_key(
  so_name: string,
  callback: (ctx: InvocationContext, model: CallbackModel) => void = () => {}
) {
  let prefix = `[ ${so_name} ]`;
  var AES_set_encrypt_key_ptr = Module.getExportByName(
    so_name,
    "AES_set_encrypt_key"
  );
  // AES_set_encrypt_key
  Interceptor.attach(AES_set_encrypt_key_ptr, {
    onEnter: function (args) {
      this.data_ptr = args[0];
      this.size = 16;
      let func_info = `onEnter AES_set_encrypt_key { size: ${
        this.size
      } size_hex: 0x${this.size.toString(16)} }\n`;
      console.log(prefix, func_info, this.data_ptr.readByteArray(this.size));
      // callback
      let model = new CallbackModel();
      model.setFunction("AES_set_encrypt_key");
      model.setData(this.data_ptr.readByteArray(this.size));
      callback(this, model);
    },
    onLeave: function (retval) {},
  });
}
export function hook_aes_cbc_encrypt(so_name: string) {
  let prefix = `[ ${so_name} ]`;
  var AES_cbc_encrypt_ptr = Module.getExportByName(so_name, "AES_cbc_encrypt");
  // AES_cbc_encrypt
  // void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
  //   size_t len, const AES_KEY *key,
  //   unsigned char *ivec, const int enc)
  Interceptor.attach(AES_cbc_encrypt_ptr, {
    onEnter: function (args) {
      this.in_ptr = args[0];
      this.out_ptr = args[1];
      this.len = args[2].toInt32();
      this.iv_ptr = args[4];
      this.mode = args[5];
      this.ivl = 16;
      let in_func_info = `onEnter AES_cbc_encrypt in_ptr { mode: ${
        this.mode
      } size: ${this.len} size_hex: 0x${this.len.toString(16)} }\n`;
      console.log(prefix, in_func_info, this.in_ptr.readByteArray(this.len));
      let iv_func_info = `onEnter AES_cbc_encrypt iv_ptr { mode: ${
        this.mode
      } size: ${this.ivl} size_hex: 0x${this.ivl.toString(16)} }\n`;
      console.log(prefix, iv_func_info, this.iv_ptr.readByteArray(this.ivl));
    },
    onLeave: function (retval) {
      let out_func_info = `onLeave AES_cbc_encrypt out_ptr { mode: ${
        this.mode
      } size: ${this.len} size_hex: 0x${this.len.toString(16)} }\n`;
      console.log(prefix, out_func_info, this.out_ptr.readByteArray(this.len));
    },
  });
}
export function hook_crypto_cbc128_encrypt(so_name: string) {
  let prefix = `[ ${so_name} ]`;
  var CRYPTO_cbc128_encrypt_ptr = Module.getExportByName(
    so_name,
    "CRYPTO_cbc128_encrypt"
  );
  // CRYPTO_cbc128_encrypt
  // void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
  //   size_t len, const void *key,
  //   unsigned char ivec[16], block128_f block)
  Interceptor.attach(CRYPTO_cbc128_encrypt_ptr, {
    onEnter: function (args) {
      this.in_ptr = args[0];
      this.out_ptr = args[1];
      this.len = args[2].toInt32();
      this.iv_ptr = args[4];
      this.ivl = 16;
      let in_func_info = `onEnter CRYPTO_cbc128_encrypt in_ptr { size: ${
        this.len
      } size_hex: 0x${this.len.toString(16)} }\n`;
      console.log(prefix, in_func_info, this.in_ptr.readByteArray(this.len));
      let iv_func_info = `onEnter CRYPTO_cbc128_encrypt iv_ptr { size: ${
        this.ivl
      } size_hex: 0x${this.ivl.toString(16)} }\n`;
      console.log(prefix, iv_func_info, this.iv_ptr.readByteArray(this.ivl));
    },
    onLeave: function (retval) {
      let out_func_info = `onLeave CRYPTO_cbc128_encrypt out_ptr { size: ${
        this.len
      } size_hex: 0x${this.len.toString(16)} }\n`;
      console.log(prefix, out_func_info, this.out_ptr.readByteArray(this.len));
    },
  });
}
