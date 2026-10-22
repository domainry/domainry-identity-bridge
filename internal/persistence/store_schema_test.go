package persistence

import (
	"strings"
	"testing"

	"github.com/domainry/domainry-foundation/schemaownership"
	"github.com/domainry/domainry-orm/dialect"
)

func TestExternalIdentityStateOwnershipHasNoEntityID(t *testing.T) {
	tables := SchemaOwnership()
	if err := schemaownership.ValidateAll(tables); err != nil {
		t.Fatal(err)
	}
	if len(tables) != 1 || tables[0].Kind != schemaownership.KindState || tables[0].EntityIDColumn != "" || len(tables[0].BusinessKey) != 0 {
		t.Fatalf("external Identity state manufactured an entity identity: %#v", tables)
	}
}

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
	upper := strings.ToUpper(statement)
	if !strings.Contains(upper, "`ID` BIGINT NOT NULL AUTO_INCREMENT") || !strings.Contains(upper, "PRIMARY KEY (`ID`)") || !strings.Contains(upper, "UNIQUE (`STATE_KEY`)") {
		t.Fatalf("external Identity state must use a physical id and retain state_key as a natural unique key: %s", statement)
	}
}
