import { Jni } from "../modules/jnitrace/Jni";
import { Libart } from "../modules/libart/Libart";
import { Libc } from "../modules/libc/Libc";
import { SSL } from "../modules/ssl/SSL";
import { Linker } from "../modules/linker/Linker";
class FPCore {
  private _jni_module = new Jni();
  private _libart_module = new Libart();
  private _libc_module = new Libc();
  private _ssl_module = new SSL();
  private _linker_module = new Linker();
  public get jni() {
    return this._jni_module;
  }
  public get libart() {
    return this._libart_module;
  }
  public get libc() {
    return this._libc_module;
  }
  public get ssl() {
    return this._ssl_module;
  }
  public get linker() {
    return this._linker_module;
  }
}

export const fpcore = new FPCore();
