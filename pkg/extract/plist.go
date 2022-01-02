package extract

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strconv"
)

// original source is from: https://github.com/RedMapleTech/machodump

// getEntsFromXMLString extracts the entitlements from an XML string
func getEntsFromXMLString(entString string) (*entsStruct, error) {

	bytes := []byte(entString)

	if len(bytes) < 1 {
		return nil, fmt.Errorf("No entitlements string")
	}

	ents, err := processPlist(bytes)

	if err != nil {
		return nil, fmt.Errorf("failed to decode xml plist: %s", err.Error())
	}

	return ents, nil
}

type stringArray struct {
	Strings []string `xml:"string"`
}

// entsStruct to hold all the entitlements
type entsStruct struct {
	BooleanValues     []booleanEntry
	IntegerValues     []integerEntry
	StringValues      []stringEntry
	StringArrayValues []stringArrayEntry
}

type booleanEntry struct {
	Name  string
	Value bool
}

type stringEntry struct {
	Name  string
	Value string
}

type integerEntry struct {
	Name  string
	Value int
}

type stringArrayEntry struct {
	Name   string
	Values []string
}

// Function to unmarshal the XML plist data
// Annoying structure means we have to do it token by token
// as each entry is a key followed by either trues, strings or arrays
// and we need to match keys to entries
func processPlist(data []byte) (*entsStruct, error) {

	r := bytes.NewReader(data)
	decoder := xml.NewDecoder(r)

	keys := 0
	values := 0
	lastKey := ""

	var ents entsStruct

	for {
		// Read tokens from the XML document in a stream.
		thisToken, err := decoder.Token()

		if thisToken == nil || err != nil {
			break
		}

		// Inspect the type of the token just read.
		switch thisToken := thisToken.(type) {
		default:
			//log.Printf("Unknown type: %v", thisToken)
		case xml.EndElement:
			//log.Printf("End %v", thisToken)
		case xml.CharData:
			//log.Printf("CharData %v", thisToken)
		case xml.Comment:
			//log.Printf("Comment %v", thisToken)
		case xml.ProcInst:
			//log.Printf("ProcInst %v", thisToken)
		case xml.Directive:
			//log.Printf("Directive %v", thisToken)
		// start element is the only one we care about
		case xml.StartElement:
			element := thisToken.Name.Local

			switch element {

			case "key":
				var key string
				err := decoder.DecodeElement(&key, &thisToken)

				if err == nil {
					keys++

					// if it's a key just store it to use with the next entry
					lastKey = key
				}

			case "true":
				var entry booleanEntry
				entry.Name = lastKey
				entry.Value = true
				ents.BooleanValues = append(ents.BooleanValues, entry)
				values++

			case "false":
				var entry booleanEntry
				entry.Name = lastKey
				entry.Value = false
				ents.BooleanValues = append(ents.BooleanValues, entry)
				values++

			case "dict":
				// if it's not the first dict, will be a sub dict
				if lastKey != "" {
					// it will be processed in turn, so just add it to the count
					values++
				}

			case "string":
				var value string
				err := decoder.DecodeElement(&value, &thisToken)

				if err == nil {
					//log.Printf("String %s: %q", lastKey, value)

					var entry stringEntry
					entry.Name = lastKey
					entry.Value = value
					ents.StringValues = append(ents.StringValues, entry)

					values++
				}

			case "integer":
				var value string
				err := decoder.DecodeElement(&value, &thisToken)

				if err == nil {
					//log.Printf("String %s: %q", lastKey, value)

					var entry integerEntry
					entry.Name = lastKey
					valueInt, _ := strconv.Atoi(value)
					entry.Value = valueInt
					ents.IntegerValues = append(ents.IntegerValues, entry)
					values++
				}

			case "array":
				var arr stringArray
				err := decoder.DecodeElement(&arr, &thisToken)

				if err == nil {
					var entry stringArrayEntry
					entry.Name = lastKey

					for _, str := range arr.Strings {
						entry.Values = append(entry.Values, str)
					}

					ents.StringArrayValues = append(ents.StringArrayValues, entry)

					values++
				}
			}
		}
	}

	if keys != values {
		return nil, fmt.Errorf("Mismatched numbers of keys (%d) and values (%d)", keys, values)
	}

	return &ents, nil
}
