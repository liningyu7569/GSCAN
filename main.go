// main.go
// 这个文件是 GoScan 项目的入口点。它负责启动 CLI（命令行界面）。
// 在 Go 语言中，main() 函数是程序的起点。
// 这里我们导入 cmd 包，并调用其 Execute() 函数来处理命令行输入。
// 为什么这样设计？因为 Cobra（我们使用的 CLI 库）将命令逻辑放在 cmd 包中，便于模块化。
package main

import (
	"Going_Scan/cmd" // 导入自定义的 cmd 包，其中包含 CLI 命令定义。
)

func main() {
	// 调用 cmd 包的 Execute() 函数，启动 CLI 处理。
	// 如果有命令行参数（如 "scan 127.0.0.1"），它会解析并执行相应逻辑。
	cmd.Execute()
}
