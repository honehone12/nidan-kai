package schema

import (
	"nidan-kai/binid"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// User holds the schema definition for the User entity.
type User struct {
	ent.Schema
}

// Fields of the User.
func (User) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", binid.BinId{}).
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.String("name").
			NotEmpty().
			MaxLen(256),
		field.String("email").
			NotEmpty().
			MaxLen(256).
			Unique(),
		field.Enum("login_method").
			Values(
				"password",
				"mfa-qr",
				"passkey",
			).
			Default("password"),
	}
}

// Edges of the User.
func (User) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("mfa_qrs", MfaQr.Type).
			Immutable(),
	}
}

func (User) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("email").Unique(),
	}
}

func (User) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
