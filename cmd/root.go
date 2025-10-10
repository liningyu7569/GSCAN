// cmd/root.go
// 这个文件定义了 CLI 的根命令和子命令，使用 Cobra 库。
// Cobra 是 Go 的流行 CLI 框架，允许定义命令、标志和子命令。
// 语法：cobra.Command 结构体定义命令，Run 字段是执行函数。
// 这里我们定义 "goscan" 根命令和 "scan" 子命令。
// 作用：解析用户输入（如 "goscan scan 127.0.0.1"），调用 scanner 包的函数进行扫描。
// 教学：Cobra 的 init() 函数用于添加子命令；Execute() 在 main.go 中调用。
package cmd

import (
	"Going_Scan/pkg/scanner" // 导入自定义 scanner 包，包含扫描逻辑。
	"fmt"                    // 标准库，用于格式化输出，如 Printf。
	"os"                     // 标准库，用于操作系统交互，如 Exit。

	"github.com/spf13/cobra" // 导入 Cobra 库，用于构建 CLI。
)

// rootCmd 是根命令 "goscan"。
// Use: 命令名称；Short: 简短描述。
var rootCmd = &cobra.Command{
	Use:   "goscan",          // 根命令的用法，例如 "goscan [command]"。
	Short: "Network Scanner", // 简短描述，在帮助信息中显示。
}

// scanCmd 是子命令 "scan"，用于扫描目标 IP。
// Use: 子命令用法；Short: 描述；Args: 验证参数（至少 1 个）。
// Run: 执行函数，当用户运行 "goscan scan [target]" 时调用。
var scanCmd = &cobra.Command{
	Use:   "scan [target]",       // 用法，例如 "scan 127.0.0.1"。
	Short: "Scan target IP",      // 简短描述。
	Args:  cobra.MinimumNArgs(1), // 至少需要 1 个参数（目标 IP）。
	Run: func(cmd *cobra.Command, args []string) { // Run 函数：cmd 是当前命令，args 是参数列表。
		target := args[0] // 获取第一个参数作为目标 IP。

		// 调用 scanner.PingHost() 测试主机是否活跃。
		// 这是一个 ICMP Echo 请求，用于主机发现。
		alive, err := scanner.PingHost(target)
		if err != nil { // 如果错误，打印并返回。
			fmt.Printf("Error: %v\n", err) // fmt.Printf：格式化打印，%v 是默认格式。
			return
		}
		fmt.Printf("Host %s alive: %v\n", target, alive) // 打印结果。

		// 调用 scanner.ScanTCPPort() 测试端口 80（HTTP）。
		// 这是一个 TCP SYN 扫描，用于检查端口状态。
		status, err := scanner.ScanTCPPort(target, 80)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		fmt.Printf("Port 80: %s\n", status) // 打印端口状态（open/closed/filtered）。
	},
}

// init() 是 Go 的特殊函数，在包初始化时自动调用。
// 这里用于将 scanCmd 添加到 rootCmd。
func init() {
	rootCmd.AddCommand(scanCmd) // 将 "scan" 添加为子命令。
}

// Execute() 是公开函数，用于从 main.go 调用。
// 它执行根命令，并处理错误（如无效命令）。
func Execute() {
	if err := rootCmd.Execute(); err != nil { // 执行根命令，如果错误：
		fmt.Fprintf(os.Stderr, "Error: %v\n", err) // 打印到标准错误输出。
		os.Exit(1)                                 // 以退出码 1 结束程序（表示错误）。
	}
}
