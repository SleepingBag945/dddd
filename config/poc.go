package config

import (
	"embed"
	"io/fs"
	"strings"
)

//go:embed pocs
var Pocs embed.FS

// 搜索内容包含appName关键字的全部文件
func SelectPoc(appName string) (result []string) {
	list, _ := New("").GetTemplatePath(Pocs)
	for _, f := range list {
		data, _ := Pocs.ReadFile(f)
		if strings.Contains(strings.ToLower(string(data)), strings.ToLower(appName)) {
			result = append(result, f)
		}
	}
	return
}

// Catalog is a template catalog helper implementation
type Catalog struct {
	templatesDirectory string
}

// New creates a new Catalog structure using provided input items
func New(directory string) *Catalog {
	catalog := &Catalog{templatesDirectory: directory}
	return catalog
}

// GetTemplatePath parses the specified input template path and returns a compiled
// list of finished absolute paths to the templates evaluating any glob patterns
// or folders provided as in.
func (c *Catalog) GetTemplatePath(Pocs embed.FS) ([]string, error) {
	processed := make(map[string]struct{})
	// Recursively walk down the Templates directory and run all
	// the template file checks
	matches, err := c.findDirectoryMatches(Pocs, processed)
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, err
	}
	return matches, nil
}

// findDirectoryMatches finds matches for templates from a directory
func (c *Catalog) findDirectoryMatches(Pocs embed.FS, processed map[string]struct{}) ([]string, error) {
	var results []string
	err := fs.WalkDir(Pocs, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			if _, ok := processed[path]; !ok {
				results = append(results, path)
				processed[path] = struct{}{}
			}
		}
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			results = append(results, path)
		}
		return nil
	})
	return results, err
}
