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
  const formatArg = (arg: any): string => {
    if (arg instanceof ArrayBuffer) {
      return hexdump(arg, { ansi: false, header: false });
    }
    return String(arg);
  };
  const formattedArgs = args.map(formatArg);
  originalLog(prefix, ...formattedArgs, postfix);
  send({
    type: "log",
    payload: `${prefix} ${formattedArgs.join(" ")} ${postfix}`,
  });
};
// main
function main() {
  entry();
}

setImmediate(main);
