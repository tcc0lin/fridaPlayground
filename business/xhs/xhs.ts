import { fpcore } from "../../core/FPCore";
export function entry() {
  fpcore.libart.hook_register_native();
}
