package kubeval

import (
	"fmt"
	"github.com/hashicorp/go-multierror"
	"github.com/xeipuuv/gojsonschema"
	"sync"
)

type SchemaDownloader interface {
	// returned schema may be nil scehma is missing and missing schemas are allowed
	SchemaDownload(versionKind string, schemaRefs []string) (*gojsonschema.Schema, error)
}

type CachedSchemaDownloader struct {
	sync.Mutex
	schemaDownloader SchemaDownloader
	schemaCache map[string]*gojsonschema.Schema
}

func (csd *CachedSchemaDownloader) SchemaDownload (versionKind string, schemaRefs []string) (*gojsonschema.Schema, error) {
	csd.Lock()
	defer csd.Unlock()

	if schema, ok := csd.schemaCache[versionKind]; ok {
		return schema, nil
	}

	schema, err := csd.schemaDownloader.SchemaDownload(versionKind, schemaRefs)
	if err != nil {
		csd.schemaCache[versionKind] = nil
		return schema, err
	}
	csd.schemaCache[versionKind] = schema

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

func (ssd *SimpleSchemaDownloader) SchemaDownload (versionKind string, schemaRefs []string) (*gojsonschema.Schema, error) {
	// We haven't cached this schema yet; look for one that works
	//primarySchemaBaseURL := determineSchemaBaseURL(isOpenShift, schemaLocation)
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
