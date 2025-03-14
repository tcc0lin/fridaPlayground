export function find_RegisterNatives() {
  let symbols = Module.load("libart.so").enumerateSymbols();
  let addrRegisterNatives = null;
  for (let i = 0; i < symbols.length; i++) {
    let symbol = symbols[i];
    //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
    if (
      symbol.name.indexOf("art") >= 0 &&
      symbol.name.indexOf("JNI") >= 0 &&
      symbol.name.indexOf("RegisterNatives") >= 0 &&
      symbol.name.indexOf("CheckJNI") < 0
    ) {
      console.log(symbol.name);
      addrRegisterNatives = symbol.address;
      console.log("RegisterNatives is at ", symbol.address, symbol.name);
      hook_RegisterNatives(addrRegisterNatives);
    }
  }
}

function hook_RegisterNatives(addrRegisterNatives: NativePointer) {
  if (addrRegisterNatives != null) {
    Interceptor.attach(addrRegisterNatives, {
      onEnter: function (args) {
        console.log("[RegisterNatives] method_count:", args[3]);
        let java_class = args[1];
        let class_name = Java.vm.tryGetEnv().getClassName(java_class);
        //console.log(class_name);
        let methods_ptr = args[2];
        let method_count = args[3].toInt32();
        for (let i = 0; i < method_count; i++) {
          let name_ptr = methods_ptr
            .add(i * Process.pointerSize * 3)
            .readPointer();
          let sig_ptr = methods_ptr
            .add(i * Process.pointerSize * 3 + Process.pointerSize)
            .readPointer();
          let fnPtr_ptr = methods_ptr
            .add(i * Process.pointerSize * 3 + Process.pointerSize * 2)
            .readPointer();
          let name = name_ptr.readCString();
          let sig = sig_ptr.readCString();
          let symbol = DebugSymbol.fromAddress(fnPtr_ptr);
          console.log(
            "[RegisterNatives] java_class:",
            class_name,
            "name:",
            name,
            "sig:",
            sig,
            "fnPtr:",
            fnPtr_ptr,
            " fnOffset:",
            symbol,
            " callee:",
            DebugSymbol.fromAddress(this.returnAddress)
          );
        }
      },
    });
  }
}
