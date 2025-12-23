package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// MfaQr holds the schema definition for the MfaQr entity.
type MfaQr struct {
	ent.Schema
}

// Fields of the MfaQr.
func (MfaQr) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.Bytes("secret").
			NotEmpty().
			Immutable().
			MinLen(32).
			MaxLen(256).
			SchemaType(map[string]string{dialect.MySQL: "varbinary"}),
		field.String("user_id").
			NotEmpty().
			Immutable().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
	}
}

// Edges of the MfaQr.
func (MfaQr) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("mfa_qrs").
			Field("user_id").
			Required().
			Immutable().
			Unique(),
	}
}

func (MfaQr) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
