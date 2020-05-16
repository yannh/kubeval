package schemadownloader

import (
	"crypto/md5"
	"fmt"
	"github.com/hashicorp/go-multierror"
	"github.com/xeipuuv/gojsonschema"
	"sync"
)

type SchemaDownloader interface {
	// returned schema may be nil scehma is missing and missing schemas are allowed
	SchemaDownload(schemaRefs []string) (*gojsonschema.Schema, error)
}

type CachedSchemaDownloader struct {
	sync.Mutex
	schemaDownloader SchemaDownloader
	schemaCache map[[16]byte]*gojsonschema.Schema
}

func schemaRefsHash(schemaRefs []string)[16]byte {
	serialized := ""
	for _, ref := range schemaRefs {
		serialized += ref
	}

	return md5.Sum([]byte(serialized))
}

func (csd *CachedSchemaDownloader) SchemaDownload (schemaRefs []string) (*gojsonschema.Schema, error) {
	csd.Lock()
	defer csd.Unlock()

	key := schemaRefsHash(schemaRefs)

	if schema, ok := csd.schemaCache[key]; ok {
		return schema, nil
	}
	schema, err := csd.schemaDownloader.SchemaDownload(schemaRefs)
	if err != nil {
		csd.schemaCache[key] = nil
		return schema, err
	}
	csd.schemaCache[key] = schema

	return schema, nil
}

func WithCache(schemaDownloader SchemaDownloader) *CachedSchemaDownloader {
	return &CachedSchemaDownloader{
		schemaCache: make(map[[16]byte]*gojsonschema.Schema, 0),
		schemaDownloader: schemaDownloader,
	}
}

type SimpleSchemaDownloader struct {
}

func (ssd *SimpleSchemaDownloader) SchemaDownload (schemaRefs []string) (*gojsonschema.Schema, error) {
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

	// We couldn't find a schema for this resource
	return nil, errors.ErrorOrNil()
}

func NewSchemaDownloader() *SimpleSchemaDownloader {
	return &SimpleSchemaDownloader{}
}
