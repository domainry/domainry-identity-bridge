package persistence

import (
	"strings"
	"testing"

	"github.com/domainry/domainry-orm/dialect"
)

func TestMySQLExternalIdentityPayloadUsesLongText(t *testing.T) {
	renderer, err := dialect.ParseRenderer("mysql", "", "")
	if err != nil {
		t.Fatal(err)
	}
	statement, args, err := stateTableDDL(renderer)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 0 {
		t.Fatalf("unexpected DDL arguments: %#v", args)
	}
	if !strings.Contains(strings.ToUpper(statement), "`PAYLOAD` LONGTEXT NOT NULL") {
		t.Fatalf("external Identity payload must hold complete permission publications on MySQL: %s", statement)
	}
}
