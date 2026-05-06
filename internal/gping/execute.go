package gping

import (
	"context"
	"fmt"
)

// executeAction 按路由分发执行动作：raw（原始包）、stack（协议栈）或 app（应用层适配器）
func executeAction(ctx context.Context, target TargetContext, action ActionUnit) (routeEvidence, error) {
	switch normalizeRoute(action.Route) {
	case "raw":
		return executeRaw(ctx, target, action)
	case "stack":
		return executeStack(ctx, target, action)
	case "app":
		return executeApp(ctx, target, action)
	default:
		return routeEvidence{}, fmt.Errorf("unsupported gping route %q", action.Route)
	}
}
