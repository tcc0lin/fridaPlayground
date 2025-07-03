import { hook_socket } from "./hook_socket";
import { hook_file_op } from "./hook_file_op";
export class Libc {
  public hook_socket(): void {
    hook_socket();
  }
  public hook_file_op(target: string[] = []): void {
    hook_file_op(target);
  }
}
