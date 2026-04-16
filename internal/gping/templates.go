package gping

import (
	"embed"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed templates/*/*.yaml
var builtinTemplates embed.FS

func LoadTemplate(name string) (TemplateSpec, error) {
	templates, err := loadBuiltinTemplates()
	if err != nil {
		return TemplateSpec{}, err
	}
	if spec, ok := templates[strings.TrimSpace(name)]; ok {
		return spec, nil
	}
	if fileExists(name) {
		return loadTemplateFile(name)
	}
	return TemplateSpec{}, fmt.Errorf("unknown gping template %q", name)
}

func loadBuiltinTemplates() (map[string]TemplateSpec, error) {
	entries, err := builtinTemplates.ReadDir("templates")
	if err != nil {
		return nil, err
	}

	out := make(map[string]TemplateSpec)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		children, err := builtinTemplates.ReadDir(filepath.Join("templates", entry.Name()))
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			if child.IsDir() || !strings.HasSuffix(child.Name(), ".yaml") {
				continue
			}
			spec, err := loadTemplateBytes(filepath.Join("templates", entry.Name(), child.Name()))
			if err != nil {
				return nil, err
			}
			out[spec.Name] = spec
		}
	}
	return out, nil
}

func loadTemplateFile(path string) (TemplateSpec, error) {
	return loadTemplateBytes(path)
}

func loadTemplateBytes(path string) (TemplateSpec, error) {
	var (
		raw []byte
		err error
	)
	if strings.HasPrefix(path, "templates/") {
		raw, err = builtinTemplates.ReadFile(path)
	} else {
		raw, err = osReadFile(path)
	}
	if err != nil {
		return TemplateSpec{}, err
	}

	var spec TemplateSpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		return TemplateSpec{}, fmt.Errorf("parse template %s: %w", path, err)
	}
	if strings.TrimSpace(spec.Name) == "" {
		return TemplateSpec{}, fmt.Errorf("template %s is missing name", path)
	}
	if len(spec.Steps()) == 0 {
		return TemplateSpec{}, fmt.Errorf("template %s has no actions", path)
	}
	return spec, nil
}
