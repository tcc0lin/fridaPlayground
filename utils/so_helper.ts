export function hook_exports(so_name: string, filters: string[] = []) {
  let methods = Module.load(so_name).enumerateExports();
  methods.forEach((exp: ModuleExportDetails) => {
    if (exp.type !== "function") return;
    if (exp.name.startsWith("_Z")) return;
    for (let index = 0; index < filters.length; index++) {
      const element = filters[index];
      if (exp.name.indexOf(element) == -1) {
        return;
      }
    }
    try {
      Interceptor.attach(exp.address, {
        onEnter(args) {
          console.log("call: ", exp.name);
        },
      });
    } catch (e) {
      console.warn(`[!] Hook ${exp.name} 失败: ${e}`);
    }
  });
}
