// import { entry } from "../business/xhs/xhs";
import { entry } from "../business/wework/wework";
// import { entry } from "../business/wechat/wechat";
// custom log
let originalLog = console.log;
console.log = (...args: any[]) => {
  let timestamp = new Date();
  let tid = Process.getCurrentThreadId();
  let prefix = `${timestamp} ${tid}`;
  let postfix = "\n" + "*".repeat(120);
  originalLog(prefix, ...args, postfix);
};
// main
function main() {
  entry();
}

setImmediate(main);
