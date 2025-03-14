export function hook_socket(): void {
  var sendtoPtr = Module.getExportByName("libc.so", "sendto");
  var recvfromPtr = Module.getExportByName("libc.so", "recvfrom");
  var writePtr = Module.getExportByName("libc.so", "write");
  var readPtr = Module.getExportByName("libc.so", "read");
  let prefix = `[ libc.so ]`;
  // sendto
  Interceptor.attach(sendtoPtr, {
    onEnter: function (args) {
      var fd = args[0];
      var buf = args[1];
      var size = args[2].toInt32();
      var sockdata = getSocketData(fd.toInt32());
      if (
        sockdata == "" ||
        sockdata.indexOf("null") != -1 ||
        sockdata.indexOf("unix:stream") != -1
      ) {
        return;
      }
      let func_info = `onEnter sendto { fd: ${fd} sockdata: ${sockdata} size: ${size} size_hex: 0x${size.toString(
        16
      )} }\n`;
      console.log(prefix, func_info, buf.readByteArray(size));
    },
    onLeave: function (retval) {},
  });
  // recvfrom
  Interceptor.attach(recvfromPtr, {
    onEnter: function (args) {
      var fd = args[0];
      var buf = args[1];
      var size = args[2].toInt32();
      var sockdata = getSocketData(fd.toInt32());
      if (
        sockdata == "" ||
        sockdata.indexOf("null") != -1 ||
        sockdata.indexOf("unix:stream") != -1
      ) {
        return;
      }
      let func_info = `onEnter recvfrom { fd: ${fd} sockdata: ${sockdata} size: ${size} size_hex: 0x${size.toString(
        16
      )} }\n`;
      console.log(prefix, func_info, buf.readByteArray(size));
    },
    onLeave: function (retval) {},
  });
  // write
  Interceptor.attach(writePtr, {
    onEnter(args) {
      var fd = args[0];
      var buf = args[1];
      var size = args[2].toInt32();
      var sockdata = getSocketData(fd.toInt32());
      if (
        sockdata == "" ||
        sockdata.indexOf("null") != -1 ||
        sockdata.indexOf("unix:stream") != -1
      ) {
        return;
      }
      let func_info = `onEnter write { fd: ${fd} sockdata: ${sockdata} size: ${size} size_hex: 0x${size.toString(
        16
      )} }\n`;
      console.log(prefix, func_info, buf.readByteArray(size));
    },
  });
  // read
  Interceptor.attach(readPtr, {
    onEnter(args) {
      this.fd = args[0];
      this.buf = args[1];
      this.size = args[2].toInt32();
    },
    onLeave(retval) {
      var sockdata = getSocketData(this.fd.toInt32());
      if (
        sockdata == "" ||
        sockdata.indexOf("null") != -1 ||
        sockdata.indexOf("unix:stream") != -1
      ) {
        return;
      }
      const len = retval.toInt32();
      if (len < 0) {
        return;
      }
      let func_info = `onEnter read { fd: ${
        this.fd
      } sockdata: ${sockdata} size: ${len} size_hex: 0x${len.toString(16)} }\n`;
      console.log(prefix, func_info, this.buf.readByteArray(retval.toInt32()));
    },
  });
}

function getSocketData(fd: number): string {
  var socketType = Socket.type(fd);
  if (socketType != null) {
    var res =
      "type:" +
      socketType +
      ",loadAddress:" +
      JSON.stringify(Socket.localAddress(fd)) +
      ",peerAddress" +
      JSON.stringify(Socket.peerAddress(fd));
    return res;
  } else {
    return "";
  }
}
