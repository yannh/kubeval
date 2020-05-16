package kubeval

import (
	"fmt"
	"github.com/hashicorp/go-multierror"
	"github.com/xeipuuv/gojsonschema"
	"sync"
)

type SchemaDownloader interface {
	// returned schema may be nil scehma is missing and missing schemas are allowed
	SchemaDownload(kind string, APIVersion string, primarySchemaBaseURL string, additionalSchemaLocations []string, kubernetesVersion string, isOpenShift bool, strict bool) (*gojsonschema.Schema, error)
}

type CachedSchemaDownloader struct {
	sync.Mutex
	schemaDownloader SchemaDownloader
	schemaCache map[string]*gojsonschema.Schema
}

func (csd *CachedSchemaDownloader) SchemaDownload (kind string, APIVersion string, primarySchemaBaseURL string, additionalSchemaLocations []string, kubernetesVersion string, isOpenShift bool, strict bool) (*gojsonschema.Schema, error) {
	csd.Lock()
	defer csd.Unlock()

	if schema, ok := csd.schemaCache[kind]; ok {
		return schema, nil
	}

	schema, err := csd.schemaDownloader.SchemaDownload(kind, APIVersion, primarySchemaBaseURL, additionalSchemaLocations, kubernetesVersion, isOpenShift, strict)
	if err != nil {
		csd.schemaCache[kind] = nil
		return schema, err
	}
	csd.schemaCache[kind] = schema

	return schema, nil
}

func WithCache(schemaDownloader SchemaDownloader) *CachedSchemaDownloader {
	return &CachedSchemaDownloader{
		schemaCache: make(map[string]*gojsonschema.Schema, 0),
		schemaDownloader: schemaDownloader,
	}
}

type SimpleSchemaDownloader struct {
}

func (ssd *SimpleSchemaDownloader) SchemaDownload (kind string, APIVersion string, primarySchemaBaseURL string, additionalSchemaLocations []string, kubernetesVersion string, isOpenShift bool, strict bool) (*gojsonschema.Schema, error) {
	// We haven't cached this schema yet; look for one that works
	//primarySchemaBaseURL := determineSchemaBaseURL(isOpenShift, schemaLocation)
	primarySchemaRef := determineSchemaURL(primarySchemaBaseURL, kind, APIVersion, kubernetesVersion, isOpenShift, strict)
	schemaRefs := []string{primarySchemaRef}

	for _, additionalSchemaURLs := range additionalSchemaLocations {
		additionalSchemaRef := determineSchemaURL(additionalSchemaURLs, kind, APIVersion, kubernetesVersion, isOpenShift, strict)
		schemaRefs = append(schemaRefs, additionalSchemaRef)
	}

	var errors *multierror.Error

	for _, schemaRef := range schemaRefs {
		schemaLoader := gojsonschema.NewReferenceLoader(schemaRef)
		schema, err := gojsonschema.NewSchema(schemaLoader)
		if err == nil {
			// success! return this and stop looking
			return schema, nil
		}
		// We couldn't find a schema for this URL, so take a note, then try the next URL
		wrappedErr := fmt.Errorf("Failed initializing schema %s: %s", schemaRef, err)
		errors = multierror.Append(errors, wrappedErr)
	}

	if errors != nil {
		errors.ErrorFormat = singleLineErrorFormat
	}

	// We couldn't find a schema for this resource
	return nil, errors.ErrorOrNil()
}

func NewSchemaDownloader() *SimpleSchemaDownloader {
	return &SimpleSchemaDownloader{}
}
