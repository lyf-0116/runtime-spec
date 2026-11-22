package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/xeipuuv/gojsonschema"
)

const usage = `Validate is used to check document with specified schema.
You can use validate in following ways:

   1.specify document file as an argument
      validate <schema.json> <document.json>

   2.pass document content through a pipe
      cat <document.json> | validate <schema.json>

   3.input document content manually, ended with ctrl+d(or your self-defined EOF keys)
      validate <schema.json>
      [INPUT DOCUMENT CONTENT HERE]
`

func main() {
	nargs := len(os.Args[1:])
	if nargs == 0 || nargs > 2 {
		fmt.Printf("ERROR: invalid arguments number\n\n%s\n", usage)
		os.Exit(1)
	}

	if os.Args[1] == "help" ||
		os.Args[1] == "--help" ||
		os.Args[1] == "-h" {
		fmt.Printf("%s\n", usage)
		os.Exit(1)
	}

	schemaPath := os.Args[1]
	if !strings.Contains(schemaPath, "://") {
		var err error
		schemaPath, err = formatFilePath(schemaPath)
		if err != nil {
			fmt.Printf("ERROR: invalid schema-file path: %s\n", err)
			os.Exit(1)
		}
		schemaPath = "file://" + schemaPath
	}

	documentBytes, err := loadDocumentBytes(nargs)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	schemaLoader := gojsonschema.NewReferenceLoader(schemaPath)
	documentLoader := gojsonschema.NewStringLoader(string(documentBytes))

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if result.Valid() {
		extraErrors, err := semanticChecks(schemaPath, documentBytes)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if len(extraErrors) == 0 {
			fmt.Printf("The document is valid\n")
			return
		}
		fmt.Printf("The document is not valid. see errors :\n")
		for _, desc := range extraErrors {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1)
	}

	fmt.Printf("The document is not valid. see errors :\n")
	for _, desc := range result.Errors() {
		fmt.Printf("- %s\n", desc)
	}
	os.Exit(1)
}

func loadDocumentBytes(nargs int) ([]byte, error) {
	if nargs > 1 {
		documentPath, err := formatFilePath(os.Args[2])
		if err != nil {
			return nil, err
		}
		return os.ReadFile(documentPath)
	}

	data, err := io.ReadAll(os.Stdin)
	return data, err
}

// semanticChecks enforces constraints that cannot be expressed in the JSON
// schema itself, such as cross-field contradictions and rules that only apply
// to a mount entry when the document targets a specific platform.
func semanticChecks(schemaPath string, documentBytes []byte) ([]string, error) {
	if !strings.HasSuffix(path.Base(schemaPath), "config-schema.json") {
		return nil, nil
	}

	defsPath, err := resolveSchemaFile(schemaPath, "defs-linux.json")
	if err != nil {
		return nil, err
	}

	doc := map[string]interface{}{}
	if err := json.Unmarshal(documentBytes, &doc); err != nil {
		return nil, err
	}

	return checkLinuxMounts(doc, defsPath), nil
}

func resolveSchemaFile(schemaPath, name string) (string, error) {
	schemaPath = strings.TrimPrefix(schemaPath, "file://")
	candidate := filepath.Join(filepath.Dir(schemaPath), name)
	if _, err := os.Stat(candidate); err != nil {
		return "", fmt.Errorf("ERROR: cannot locate %s next to %s: %s", name, schemaPath, err)
	}
	return candidate, nil
}

// checkLinuxMounts applies the Linux-specific mount rules. The generic Mount
// definition is shared with Solaris, FreeBSD and z/OS, whose option strings
// differ, so these checks run imperatively only for documents carrying a
// "linux" section.
func checkLinuxMounts(doc map[string]interface{}, defsPath string) []string {
	if _, ok := doc["linux"]; !ok {
		return nil
	}

	mounts, ok := doc["mounts"].([]interface{})
	if !ok {
		return nil
	}

	optionSets, err := loadLinuxMountOptionSets(defsPath)
	if err != nil {
		return []string{err.Error()}
	}

	rootReadonly := false
	if root, ok := doc["root"].(map[string]interface{}); ok {
		rootReadonly, _ = root["readonly"].(bool)
	}

	var errs []string

	for i, rawMount := range mounts {
		mount, ok := rawMount.(map[string]interface{})
		if !ok {
			continue
		}

		options, ok := mount["options"].([]interface{})
		if !ok {
			continue
		}

		location := fmt.Sprintf("mounts.%d.options", i)
		var propagation []string
		var readonly []string
		var readwrite []string

		for _, rawOption := range options {
			option, ok := rawOption.(string)
			if !ok {
				continue
			}
			if _, ok := optionSets.propagation[option]; ok {
				propagation = append(propagation, option)
			}
			if _, ok := optionSets.readonly[option]; ok {
				readonly = append(readonly, option)
			}
			if _, ok := optionSets.readwrite[option]; ok {
				readwrite = append(readwrite, option)
			}
		}

		if len(propagation) > 1 {
			errs = append(errs, fmt.Sprintf(
				"%s: mount propagation options are mutually exclusive, found %s",
				location, strings.Join(propagation, ", ")))
		}
		if len(readonly) > 0 && len(readwrite) > 0 {
			errs = append(errs, fmt.Sprintf(
				"%s: read-only options (%s) and read-write options (%s) are mutually exclusive",
				location,
				strings.Join(readonly, ", "),
				strings.Join(readwrite, ", ")))
		}
		if rootReadonly && len(readwrite) > 0 {
			errs = append(errs, fmt.Sprintf(
				"mounts.%d: read-write options (%s) conflict with root.readonly=true",
				i, strings.Join(readwrite, ", ")))
		}
	}

	return errs
}

type linuxMountOptionSets struct {
	propagation map[string]struct{}
	readonly    map[string]struct{}
	readwrite   map[string]struct{}
}

// loadLinuxMountOptionSets reads the option vocabulary from defs-linux.json so
// that the schema enum and the imperative checks share one source of truth.
func loadLinuxMountOptionSets(defsPath string) (linuxMountOptionSets, error) {
	data, err := os.ReadFile(defsPath)
	if err != nil {
		return linuxMountOptionSets{}, fmt.Errorf("ERROR: cannot load Linux mount option definitions: %s", err)
	}

	defs := struct {
		Definitions map[string]struct {
			Enum []string `json:"enum"`
		} `json:"definitions"`
	}{}
	if err := json.Unmarshal(data, &defs); err != nil {
		return linuxMountOptionSets{}, fmt.Errorf("ERROR: invalid Linux mount option definitions: %s", err)
	}

	toSet := func(name string) (map[string]struct{}, error) {
		values, ok := defs.Definitions[name]
		if !ok {
			return nil, fmt.Errorf("ERROR: definition %s missing from defs-linux.json", name)
		}
		set := make(map[string]struct{}, len(values.Enum))
		for _, value := range values.Enum {
			set[value] = struct{}{}
		}
		return set, nil
	}

	propagation, err := toSet("MountPropagationOption")
	if err != nil {
		return linuxMountOptionSets{}, err
	}
	readwrite := map[string]struct{}{}
	readonly := map[string]struct{}{}
	if values, ok := defs.Definitions["MountReadonlyOption"]; ok {
		for _, value := range values.Enum {
			switch value {
			case "ro", "rro":
				readonly[value] = struct{}{}
			case "rw", "rrw":
				readwrite[value] = struct{}{}
			}
		}
	} else {
		return linuxMountOptionSets{}, fmt.Errorf("ERROR: definition MountReadonlyOption missing from defs-linux.json")
	}

	return linuxMountOptionSets{
		propagation: propagation,
		readonly:    readonly,
		readwrite:   readwrite,
	}, nil
}

func formatFilePath(path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", err
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return absPath, nil
}
