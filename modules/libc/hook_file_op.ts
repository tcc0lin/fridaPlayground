import { print_native_stack_accurate } from "../../utils/stack"
export function hook_file_op(target: string[] = []): void {
    var openPtr = Module.getExportByName("libc.so", "open");
    var readPtr = Module.getExportByName("libc.so", "read");
    var writePtr = Module.getExportByName("libc.so", "write");
    var closePtr = Module.getExportByName("libc.so", "close");
    let prefix = `[ libc.so ]`;
    var fd_map = new Map<number, string>();
    Interceptor.attach(openPtr, {
        onEnter: function (args) {
            this.path = args[0].readUtf8String();
            this.flags = args[1].toInt32();
        },
        onLeave: function (retval) {
            let find: boolean = false;
            if (target.length == 0) {
                find = true
            } else {
                for (let feature of target) {
                    if (this.path.indexOf(feature) != -1) {
                        find = true
                        break
                    }
                }
            }
            if (!find) {
                return
            }
            let func_info = `onEnter open { path: ${this.path} flags: ${this.flags} `;
            if (retval.toInt32() < 0) {
                func_info += `error: ${retval} }`
            } else {
                this.fd = retval.toInt32();
                func_info += `success: ${this.fd} }`
                fd_map.set(this.fd, this.path)
            }
            console.log(prefix, func_info);
        }
    });
    // Interceptor.attach(readPtr, {
    //     onEnter: function (args) {
    //         this.fd = args[0].toInt32();
    //         this.buf = args[1];
    //         this.count = args[2].toInt32();
    //     },
    //     onLeave: function (retval) {
    //         const bytesRead = retval.toInt32();
    //         if (bytesRead > 0) {
    //             const data = this.buf.readByteArray(bytesRead);
    //             console.log(`[read] FD: ${this.fd}, 数据: ${bytesToHex(data)}`);
    //         } else if (bytesRead < 0) {
    //             console.log(`[read] 错误，FD: ${this.fd}, 错误码: ${bytesRead}`);
    //         }
    //     }
    // });
    Interceptor.attach(writePtr, {
        onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.count = args[2].toInt32();
            this.data = this.buf.readByteArray(this.count);
            if (fd_map.has(this.fd)) {
                let func_info = `onEnter write { path: ${fd_map.get(this.fd)} flags: ${this.fd}}\n`;
                console.log(prefix, func_info, this.data);
                // print_native_stack_accurate(this.context)
            }
        }
    });
    Interceptor.attach(closePtr, {
        onEnter: function (args) {
            this.fd = args[0].toInt32();
            let func_info = `onEnter close { path: ${fd_map.get(this.fd)} flags: ${this.fd} }`;
            // console.log(prefix, func_info);
            fd_map.delete(this.fd)
        }
    });
}
