package resourcevalidator

import (
	"fmt"
	"github.com/xeipuuv/gojsonschema"
)

// ValidFormat is a type for quickly forcing
// new formats on the gojsonschema loader
type ValidFormat struct{}

// IsFormat always returns true and meets the
// gojsonschema.FormatChecker interface
func (f ValidFormat) IsFormat(input interface{}) bool {
	return true
}

func ValidateAgainstSchema(resource interface{}, schema *gojsonschema.Schema) ([]gojsonschema.ResultError, error) {
	// Without forcing these types the schema fails to load
	// Need to Work out proper handling for these types
	gojsonschema.FormatCheckers.Add("int64", ValidFormat{})
	gojsonschema.FormatCheckers.Add("byte", ValidFormat{})
	gojsonschema.FormatCheckers.Add("int32", ValidFormat{})
	gojsonschema.FormatCheckers.Add("int-or-string", ValidFormat{})

	documentLoader := gojsonschema.NewGoLoader(resource)
	results, err := schema.Validate(documentLoader)
	if err != nil {
		// This error can only happen if the Object to validate is poorly formed. There's no hope of saving this one
		wrappedErr := fmt.Errorf("Problem validating schema. Check JSON formatting: %s", err)
		return []gojsonschema.ResultError{}, wrappedErr
	}
	if !results.Valid() {
		return results.Errors(), nil
	}

	return []gojsonschema.ResultError{}, nil
}

