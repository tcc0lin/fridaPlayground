# FridaPlayground

`FridaPlayground`是一个基于`frida`的开源工具集合，专为移动应用逆向分析、安全测试及行为监控设计。其核心优势在于
- `模块化架构`
- `灵活组件集成能力`
- `丰富的对抗案例库`

为安全研究人员和开发者提供高效、可扩展的解决方案

### 一、使用方式

```sh
$ git clone https://github.com/tcc0lin/FridaPlayground.git
$ cd FridaPlayground/
$ npm install
## after edit index.ts
$ npm run build
$ frida -U -f com.example.android -l _agent.js -o run.log
```

### 二、已支持的功能

### 三、案例参考

business目录