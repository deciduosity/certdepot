package fdepot

import (
	"github.com/square/certstrap/depot"
)

func getTagPath(tag *depot.Tag) string {
	if name := depot.GetNameFromCrtTag(tag); name != "" {
		return name + ".crt"
	}
	if name := depot.GetNameFromPrivKeyTag(tag); name != "" {
		return name + ".key"
	}
	if name := depot.GetNameFromCsrTag(tag); name != "" {
		return name + ".csr"
	}
	if name := depot.GetNameFromCrlTag(tag); name != "" {
		return name + ".crl"
	}
	return ""
}
