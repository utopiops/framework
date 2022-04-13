package utils

import (
	"os"

	"github.com/blevesearch/bleve/v2"
)

type FullTextSearcher interface {
	SetIndex(string, interface{}) error
	Search(string) ([]string, error)
}

type BleveSearch struct {
	Index bleve.Index
}

func GetNewBleveSearch() *BleveSearch {
	index, err := getBleveIndex()
	if err != nil {
		return nil
	}
	return &BleveSearch{Index: index}
}

func (b *BleveSearch) SetIndex(key string, value interface{}) error {
	return b.Index.Index(key, value)
}

func (b *BleveSearch) Search(key string) ([]string, error) {
	var results []string
	queryReq := bleve.NewMatchQuery(key)
	search := bleve.NewSearchRequest(queryReq)
	searchResults, err := b.Index.Search(search)
	if err != nil {
		return nil, err
	}
	for _, hit := range searchResults.Hits {
		results = append(results, hit.ID)
	}
	return results, nil
}

func getBleveIndex() (bleve.Index, error) {
	var bIndex bleve.Index
	var err error
	if _, err := os.Stat("example.bleve"); !os.IsNotExist(err) {
		bIndex, err = bleve.Open("example.bleve")
	} else {
		mapping := bleve.NewIndexMapping()
		bIndex, err = bleve.New("example.bleve", mapping)
	}
	return bIndex, err
}
