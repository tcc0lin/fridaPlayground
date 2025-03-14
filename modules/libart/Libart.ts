import { find_RegisterNatives } from "./hook_RegisterNatives";
export class Libart {
  public hook_register_native(): void {
    find_RegisterNatives();
  }
}
