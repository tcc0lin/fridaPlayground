import { hook_all_jni } from "./index";
export class Jni {
  public trace(): void {
    hook_all_jni();
  }
}
