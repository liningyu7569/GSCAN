package gping

import (
	"sort"
)

// ListTemplateSummaries 列出所有内建模板的摘要信息（名称、描述、动作数、路由）
func ListTemplateSummaries() ([]TemplateSummary, error) {
	templates, err := loadBuiltinTemplates()
	if err != nil {
		return nil, err
	}

	items := make([]TemplateSummary, 0, len(templates))
	for _, spec := range templates {
		steps := spec.Steps()
		routesSeen := make(map[string]struct{})
		routes := make([]string, 0, len(steps))
		for _, action := range steps {
			if _, ok := routesSeen[action.Route]; ok {
				continue
			}
			routesSeen[action.Route] = struct{}{}
			routes = append(routes, action.Route)
		}
		sort.Strings(routes)
		items = append(items, TemplateSummary{
			Name:        spec.Name,
			Description: spec.Description,
			ActionCount: len(steps),
			Routes:      routes,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Name < items[j].Name
	})
	return items, nil
}
