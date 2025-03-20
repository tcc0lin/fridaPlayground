import { hex_dump, bytearray_to_buffer } from "../../utils/buffer";
import { print_java_stack } from "../../utils/stack";

export function hook_socket_stream() {
  Java.perform(() => {
    Java.use("java.net.SocketOutputStream").socketWrite0.overload(
      "java.io.FileDescriptor",
      "[B",
      "int",
      "int"
    ).implementation = function (
      fd: any,
      bArray: number[],
      offset: number,
      len: number
    ) {
      const data = bytearray_to_buffer(bArray, offset, len);
      const hexDump = hex_dump(data);
      let func_info = `call socketWrite0 { size: ${len} size_hex: 0x${len.toString(
        16
      )} }\n`;
      console.log("", func_info, hexDump);
      var result = this.socketWrite0(fd, bArray, offset, len);
      //   print_java_stack();
      return result;
    };

    // answer for question: https://github.com/r0ysue/r0capture/issues/98
    // source code: https://github.com/google/conscrypt/blob/master/common/src/main/java/org/conscrypt/ConscryptEngineSocket.java#L746
    Java.use(
      "com.android.org.conscrypt.ConscryptEngineSocket$SSLOutputStream"
    ).writeInternal.implementation = function (buffer: Java.Wrapper) {
      const bufferCopy = buffer.duplicate();
      const size = bufferCopy.remaining();
      const javaByteArray = Java.array("byte", new Array(size).fill(0));
      bufferCopy.get(javaByteArray);
      const data = bytearray_to_buffer(javaByteArray);
      const hexDump = hex_dump(data);
      let func_info = `call writeInternal { size: ${size} size_hex: 0x${size.toString(
        16
      )} }\n`;
      console.log("", func_info, hexDump);
      this.writeInternal.apply(this, arguments);
    };
  });
}
