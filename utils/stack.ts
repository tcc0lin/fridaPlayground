export function print_java_stack(): void {
  Java.perform(function () {
    var Exception = Java.use("java.lang.Exception");
    var ins = Exception.$new("Exception");
    var straces = ins.getStackTrace();
    if (straces != undefined && straces != null) {
      var strace = straces.toString();
      var replaceStr = strace.replace(/,/g, "\r\n");
      console.log(
        "=============================Stack strat======================="
      );
      console.log(replaceStr);
      console.log(
        "=============================Stack end=======================\r\n"
      );
      Exception.$dispose();
    }
  });
}

export function print_native_stack_accurate(context: CpuContext): void {
  console.log(
    " bt mode ACCURATE from:\n" +
      Thread.backtrace(context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .join("\n") +
      "\n"
  );
}

export function print_native_stack_fuzzy(context: CpuContext): void {
  console.log(
    " bt mode FUZZY from:\n" +
      Thread.backtrace(context, Backtracer.FUZZY)
        .map(DebugSymbol.fromAddress)
        .join("\n") +
      "\n"
  );
}
