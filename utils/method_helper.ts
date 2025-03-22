function print_params(clz: Java.Wrapper, method: string, args: any[]) {
  var params = "";
  for (var idx = 0; idx < args.length; idx++) {
    params += `\nparam ${idx}: ${args[idx]}`;
  }
  console.log(
    "call overload clz: ",
    clz,
    " method: ",
    method + "\nparams: " + params
  );
}

export function hook_methods_by_class(clz: string) {
  const target_clz = Java.use(clz);
  const methods = target_clz.class.getDeclaredMethods();
  for (var idx = 0; idx < methods.length - 1; idx++) {
    let method_name = methods[idx].getName();
    try {
      var overloadAyy = target_clz[method_name].overloads;
      if (overloadAyy && overloadAyy.length > 1) {
        for (var i2 = 0; i2 < overloadAyy.length; i2++) {
          overloadAyy[i2].implementation = function (...args: any[]) {
            print_params(target_clz, method_name, args);
            return this[method_name].apply(this, arguments);
          };
          console.log(
            "hook overloads clz: ",
            target_clz,
            " method: ",
            method_name
          );
        }
      } else {
        target_clz[method_name].implementation = function (...args: any[]) {
          print_params(target_clz, method_name, args);
          return target_clz[method_name].apply(this, arguments);
        };
        console.log("hook clz: ", target_clz, " method: ", method_name);
      }
    } catch (error) {
      console.log("hook clz error: ", target_clz, method_name);
    }
  }
}
