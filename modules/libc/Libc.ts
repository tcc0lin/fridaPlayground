import { hook_socket } from "./hook_socket";
export class Libc {
  public hook_socket(): void {
    hook_socket();
  }
}
