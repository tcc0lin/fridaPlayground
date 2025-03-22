export function hook_dlopen(
  target_so: string,
  callback: () => void = () => {}
): void {
  var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
  if (android_dlopen_ext != null) {
    Interceptor.attach(android_dlopen_ext, {
      onEnter: function (args) {
        var soName = args[0].readCString();
        console.log(soName)
        if (soName != null && soName.indexOf(target_so) != -1) {
          this.find = true;
        }
      },
      onLeave: function (retval) {
        if (this.find) {
          callback();
        }
      },
    });
  }
}
