import { hook_dlopen } from "./hook_dlopen";
export class Linker {
  public hook_dlopen(target_so: string, callback: () => void = () => {}): void {
    hook_dlopen(target_so, callback);
  }
}
