package schema

import (
	"nidan-kai/binid"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// MfaQr holds the schema definition for the MfaQr entity.
type MfaQr struct {
	ent.Schema
}

// Fields of the MfaQr.
func (MfaQr) Fields() []ent.Field {
	return []ent.Field{
		field.UUID("id", binid.BinId{}).
			Immutable().
			Unique().
			SchemaType(map[string]string{dialect.MySQL: "binary(16)"}),
		field.Bytes("secret").
			NotEmpty().
			Immutable().
			MinLen(60).
			MaxLen(256).
			SchemaType(map[string]string{dialect.MySQL: "varbinary(256)"}),
		field.UUID("user_id", binid.BinId{}).
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

func (MfaQr) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "created_at").
			Annotations(entsql.IndexAnnotation{
				DescColumns: map[string]bool{"created_at": true},
			}),
	}
}

func (MfaQr) Mixin() []ent.Mixin {
	return []ent.Mixin{
		Time{},
	}
}
