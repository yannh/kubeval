package kubeval

import (
	"bytes"
	"fmt"
	"github.com/instrumenta/kubeval/pkg/schemadownloader"
	"github.com/instrumenta/kubeval/pkg/resourcevalidator"
	"os"
	"regexp"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/xeipuuv/gojsonschema"
	"sigs.k8s.io/yaml"
)

// ValidationResult contains the details from
// validating a given Kubernetes resource
type ValidationResult struct {
	FileName               string
	Kind                   string
	APIVersion             string
	ValidatedAgainstSchema bool
	Errors                 []gojsonschema.ResultError
	ResourceName           string
	ResourceNamespace      string
}

// VersionKind returns a string representation of this result's apiVersion and kind
func (v *ValidationResult) VersionKind() string {
	return v.APIVersion + "/" + v.Kind
}

// QualifiedName returns a string of the [namespace.]name of the k8s resource
func (v *ValidationResult) QualifiedName() string {
	if v.ResourceName == "" {
		return "unknown"
	} else if v.ResourceNamespace == "" {
		return v.ResourceName
	} else {
		return fmt.Sprintf("%s.%s", v.ResourceNamespace, v.ResourceName)
	}
}

func determineSchemaURL(baseURL, kind, apiVersion string, kubernetesVersion string, strict bool, isOpenShift bool) string {
	// We have both the upstream Kubernetes schemas and the OpenShift schemas available
	// the tool can toggle between then using the config.OpenShift boolean flag and here we
	// use that to format the URL to match the required specification.

	// Most of the directories which store the schemas are prefixed with a v so as to
	// match the tagging in the Kubernetes repository, apart from master.
	normalisedVersion := kubernetesVersion
	if normalisedVersion != "master" {
		normalisedVersion = "v" + normalisedVersion
	}

	strictSuffix := ""
	if strict {
		strictSuffix = "-strict"
	}

	if isOpenShift {
		// If we're using the openshift schemas, there's no further processing required
		return fmt.Sprintf("%s/%s-standalone%s/%s.json", baseURL, normalisedVersion, strictSuffix, strings.ToLower(kind))
	}

	groupParts := strings.Split(apiVersion, "/")
	versionParts := strings.Split(groupParts[0], ".")

	kindSuffix := "-" + strings.ToLower(versionParts[0])
	if len(groupParts) > 1 {
		kindSuffix += "-" + strings.ToLower(groupParts[1])
	}

	return fmt.Sprintf("%s/%s-standalone%s/%s%s.json", baseURL, normalisedVersion, strictSuffix, strings.ToLower(kind), kindSuffix)
}

func determineSchemaBaseURL(isOpenShift bool, schemaLocation string) string {
	// Order of precendence:
	// 1. If --openshift is passed, return the openshift schema location
	// 2. If a --schema-location is passed, use it
	// 3. If the KUBEVAL_SCHEMA_LOCATION is set, use it
	// 4. Otherwise, use the DefaultSchemaLocation

	if isOpenShift {
		return OpenShiftSchemaLocation
	}

	if schemaLocation != "" {
		return schemaLocation
	}

	// We only care that baseURL has a value after this call, so we can
	// ignore LookupEnv's second return value
	baseURL, _ := os.LookupEnv("KUBEVAL_SCHEMA_LOCATION")
	if baseURL != "" {
		return baseURL
	}

	return DefaultSchemaLocation
}

func resourceSchemaRefs(resource map[string]interface{}, additionalSchemaLocations []string, kubernetesVersion string, schemaLocation string, isOpenShift bool, strict bool)([]string, error){
	kind, err := getString(resource, "kind")
	if err != nil {
		return nil, err
	}

	APIVersion, err := getString(resource, "apiVersion")
	if err != nil {
		return nil, err
	}
	versionKind := fmt.Sprintf(APIVersion+"/"+kind)

	primarySchemaBaseURL := determineSchemaBaseURL(isOpenShift, schemaLocation)
	primarySchemaRef := determineSchemaURL(primarySchemaBaseURL, versionKind, APIVersion, kubernetesVersion, isOpenShift, strict)
	schemaRefs := []string{primarySchemaRef}

	for _, additionalSchemaURLs := range additionalSchemaLocations {
		additionalSchemaRef := determineSchemaURL(additionalSchemaURLs, versionKind, APIVersion, kubernetesVersion, isOpenShift, strict)
		schemaRefs = append(schemaRefs, additionalSchemaRef)
	}

	return schemaRefs, nil
}

// validateResource validates a single Kubernetes resource against
// the relevant schema, detecting the type of resource automatically.
// Returns the result and raw YAML body as map.
func validateResource(resource map[string]interface{}, downloadSchema schemadownloader.SchemaDownloader, schemaRefs []string, kindsToSkip, kindsToReject []string, ignoreMissingSchemas bool) (ValidationResult, error) {
	result := ValidationResult{}
	name, err := getStringAt(resource, []string{"metadata", "name"})
	if err != nil {
		return result, err
	}
	result.ResourceName = name

	namespace, err := getStringAt(resource, []string{"metadata", "namespace"})
	if err != nil {
		result.ResourceNamespace = "default"
	}
	result.ResourceNamespace = namespace

	kind, err := getString(resource, "kind")
	if err != nil {
		return result, err
	}
	result.Kind = kind

	apiVersion, err := getString(resource, "apiVersion")
	if err != nil {
		return result, err
	}
	result.APIVersion = apiVersion

	if in(kindsToSkip, kind) {
		return result, nil
	}

	if in(kindsToReject, kind) {
		return result, fmt.Errorf("prohibited resource kind '%s'", kind)
	}

	schema, err := downloadSchema.SchemaDownload(schemaRefs)
	if err != nil || (schema == nil && !ignoreMissingSchemas) {
		return result, fmt.Errorf("%s: %s", result.FileName, err.Error())
	}

	schemaErrors, err := resourcevalidator.ValidateAgainstSchema(resource, schema)
	if err != nil {
		return result, fmt.Errorf("%s: %s", result.FileName, err.Error())
	}

	result.ValidatedAgainstSchema = true
	result.Errors = schemaErrors

	return result, nil
}

// ValidateWithCache validates a Kubernetes YAML file, parsing out individual resources
// and validating them all according to the relevant schemas
// Allows passing a kubeval.NewSchemaCache() to cache schemas in-memory
// between validations
func Validate(fileName string, input []byte, downloadSchema schemadownloader.SchemaDownloader, config *Config) ([]ValidationResult, error) {
	results := make([]ValidationResult, 0)

	if len(config.DefaultNamespace) == 0 {
		return results, fmt.Errorf("Default namespace ('-n/--default-namespace' flag) must not be empty")
	}

	if len(input) == 0 {
		result := ValidationResult{}
		result.FileName = fileName
		results = append(results, result)
		return results, nil
	}

	list := struct {
		Version string
		Kind    string
		Items   []interface{}
	}{}

	unmarshalErr := yaml.Unmarshal(input, &list)
	isYamlList := unmarshalErr == nil && list.Items != nil && len(list.Items) > 0

	var bits [][]byte
	if isYamlList {
		bits = make([][]byte, len(list.Items))
		for i, item := range list.Items {
			b, _ := yaml.Marshal(item)
			bits[i] = b
		}
	} else {
		bits = bytes.Split(input, []byte(detectLineBreak(input)+"---"+detectLineBreak(input)))
	}

	var errors *multierror.Error

	// special case regexp for helm
	helmSourcePattern := regexp.MustCompile(`^(?:---` + detectLineBreak(input) + `)?# Source: (.*)`)
	seenResourcesSet := make(map[[4]string]bool) // set of [API version, kind, namespace, name]

	for _, element := range bits {
		if len(element) > 0 {
			if found := helmSourcePattern.FindStringSubmatch(string(element)); found != nil {
				fileName = found[1]
			}

			var body map[string]interface{}
			err := yaml.Unmarshal(element, &body)
			if err != nil {
				err = fmt.Errorf("error parsing %s: %s", fileName, err)
				errors = multierror.Append(errors, err)
				if config.ExitOnError {
					return results, errors
				} else {
					continue
				}
			}

			schemaRefs, err := resourceSchemaRefs(body, config.AdditionalSchemaLocations, config.KubernetesVersion, config.SchemaLocation, config.OpenShift, config.Strict)
			if err != nil {
				err = fmt.Errorf("%s in %s", err, fileName)
				errors = multierror.Append(errors, err)
				if config.ExitOnError {
					return results, errors
				} else {
					continue
				}
			}

			result, err := validateResource(body, downloadSchema, schemaRefs, config.KindsToSkip, config.KindsToReject, config.IgnoreMissingSchemas)
			if err != nil {
				err = fmt.Errorf("%s in %s", err, fileName)
				errors = multierror.Append(errors, err)
				if config.ExitOnError {
					return results, errors
				} else {
					continue
				}
			}

			if !in(config.KindsToSkip, result.Kind) {
				metadata, _ := getObject(body, "metadata")
				if metadata != nil {
					namespace, _ := getString(metadata, "namespace")
					name, _ := getString(metadata, "name")

					var resolvedNamespace string
					if len(namespace) > 0 {
						resolvedNamespace = namespace
					} else {
						resolvedNamespace = config.DefaultNamespace
					}

					// If resource has `metadata:name` attribute
					if len(resolvedNamespace) > 0 && len(name) > 0 {
						key := [4]string{result.APIVersion, result.Kind, resolvedNamespace, name}
						if _, hasDuplicate := seenResourcesSet[key]; hasDuplicate {
							errors = multierror.Append(errors, fmt.Errorf("%s: Duplicate '%s' resource '%s' in namespace '%s'", result.FileName, result.Kind, name, namespace))
						}

						seenResourcesSet[key] = true
					}
				}
			}
			results = append(results, result)
		} else {
			result := ValidationResult{}
			result.FileName = fileName
			results = append(results, result)
		}
	}

	if errors != nil {
		errors.ErrorFormat = singleLineErrorFormat
	}
	return results, errors.ErrorOrNil()
}

func singleLineErrorFormat(es []error) string {
	messages := make([]string, len(es))
	for i, e := range es {
		messages[i] = e.Error()
	}
	return strings.Join(messages, "\n")
}
