package AuthorizationGo

type Role struct {
	ID   uint
	Name string
}

func (r Role) TableName() string {
	return tablePrefix + "roles"
}
