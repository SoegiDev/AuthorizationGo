package AuthorizationGo

import (
	"errors"
	"gorm.io/gorm"
)

var tablePrefix string

// Authority helps deal with permissions
type AuthorizationX struct {
	DB *gorm.DB
}

type AuthOption struct {
	TablesPrefix string
	DB           *gorm.DB
}

var (
	ErrPermissionInUse     = errors.New("cannot delete assigned permission")
	ErrPermissionNotFound  = errors.New("permission not found")
	ErrRoleAlreadyAssigned = errors.New("this role is already assigned to the user")
	ErrRoleInUse           = errors.New("cannot delete assigned role")
	ErrRoleNotFound        = errors.New("role not found")
)

var authGo *AuthorizationX

// Initialization AuthorizationX
func New(authOps AuthOption) *AuthorizationX {
	tablePrefix = authOps.TablesPrefix
	authGo = &AuthorizationX{
		DB: authOps.DB,
	}

	migrateTables(authOps.DB)
	return authGo
}

func migrateTables(db *gorm.DB) {
	db.AutoMigrate(&Role{})
	db.AutoMigrate(&Permission{})
	db.AutoMigrate(&RolePermission{})
	db.AutoMigrate(&UserRole{})
}

func Resolve() *AuthorizationX {
	return authGo
}

// Create Role User
func (a *AuthorizationX) CreateRole(roleName string) error {
	var dbRole Role
	res := a.DB.Where("name = ?", roleName).First(&dbRole)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			// create
			a.DB.Create(&Role{Name: roleName})
			return nil
		}
	}

	return res.Error
}

func (a *AuthorizationX) CreatePermission(permName string) error {
	var dbPerm Permission
	res := a.DB.Where("name = ?", permName).First(&dbPerm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			// create
			a.DB.Create(&Permission{Name: permName})
			return nil
		}
	}

	return res.Error
}

func (a *AuthorizationX) AssignPermissions(roleName string, permNames []string) error {
	// get the role id
	var role Role
	rRes := a.DB.Where("name = ?", roleName).First(&role)
	if rRes.Error != nil {
		if errors.Is(rRes.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}

	}

	var perms []Permission
	// get the permissions ids
	for _, permName := range permNames {
		var perm Permission
		pRes := a.DB.Where("name = ?", permName).First(&perm)
		if pRes.Error != nil {
			if errors.Is(pRes.Error, gorm.ErrRecordNotFound) {
				return ErrPermissionNotFound
			}

		}

		perms = append(perms, perm)
	}

	// insert data into RolePermissions table
	for _, perm := range perms {
		// ignore any assigned permission
		var rolePerm RolePermission
		res := a.DB.Where("role_id = ?", role.ID).Where("permission_id =?", perm.ID).First(&rolePerm)
		if res.Error != nil {
			// assign the record
			cRes := a.DB.Create(&RolePermission{RoleID: role.ID, PermissionID: perm.ID})
			if cRes.Error != nil {
				return cRes.Error
			}
		}
	}

	return nil
}

func (a *AuthorizationX) AssignRole(userID uint, roleName string) error {
	// make sure the role exist
	var role Role
	res := a.DB.Where("name = ?", roleName).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}
	}

	// check if the role is already assigned
	var userRole UserRole
	res = a.DB.Where("user_id = ?", userID).Where("role_id = ?", role.ID).First(&userRole)
	if res.Error == nil {
		//found a record, this role is already assigned to the same user
		return ErrRoleAlreadyAssigned
	}

	// assign the role
	a.DB.Create(&UserRole{UserID: userID, RoleID: role.ID})

	return nil
}

func (a *AuthorizationX) CheckRole(userID uint, roleName string) (bool, error) {
	// find the role
	var role Role
	res := a.DB.Where("name = ?", roleName).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, ErrRoleNotFound
		}

	}

	// check if the role is a assigned
	var userRole UserRole
	res = a.DB.Where("user_id = ?", userID).Where("role_id = ?", role.ID).First(&userRole)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, nil
		}

	}

	return true, nil
}

func (a *AuthorizationX) CheckPermission(userID uint, permName string) (bool, error) {
	// the user role
	var userRoles []UserRole
	res := a.DB.Where("user_id = ?", userID).Find(&userRoles)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, nil
		}
	}

	//prepare an array of role ids
	var roleIDs []uint
	for _, r := range userRoles {
		roleIDs = append(roleIDs, r.RoleID)
	}

	// find the permission
	var perm Permission
	res = a.DB.Where("name = ?", permName).First(&perm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, ErrPermissionNotFound
		}

	}

	// find the role permission
	var rolePermission RolePermission
	res = a.DB.Where("role_id IN (?)", roleIDs).Where("permission_id = ?", perm.ID).First(&rolePermission)
	if res.Error != nil {
		return false, nil
	}

	return true, nil
}

func (a *AuthorizationX) CheckRolePermission(roleName string, permName string) (bool, error) {
	// find the role
	var role Role
	res := a.DB.Where("name = ?", roleName).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, ErrRoleNotFound
		}

	}

	// find the permission
	var perm Permission
	res = a.DB.Where("name = ?", permName).First(&perm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, ErrPermissionNotFound
		}

	}

	// find the rolePermission
	var rolePermission RolePermission
	res = a.DB.Where("role_id = ?", role.ID).Where("permission_id = ?", perm.ID).First(&rolePermission)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return false, nil
		}

	}

	return true, nil
}

func (a *AuthorizationX) RevokeRole(userID uint, roleName string) error {
	// find the role
	var role Role
	res := a.DB.Where("name = ?", roleName).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}

	}

	// revoke the role
	a.DB.Where("user_id = ?", userID).Where("role_id = ?", role.ID).Delete(UserRole{})

	return nil
}

func (a *AuthorizationX) RevokePermission(userID uint, permName string) error {
	// revoke the permission from all roles of the user
	// find the user roles
	var userRoles []UserRole
	res := a.DB.Where("user_id = ?", userID).Find(&userRoles)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return nil
		}

	}

	// find the permission
	var perm Permission
	res = a.DB.Where("name = ?", permName).First(&perm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrPermissionNotFound
		}

	}

	for _, r := range userRoles {
		// revoke the permission
		a.DB.Where("role_id = ?", r.RoleID).Where("permission_id = ?", perm.ID).Delete(RolePermission{})
	}

	return nil
}

func (a *AuthorizationX) RevokeRolePermission(roleName string, permName string) error {
	// find the role
	var role Role
	res := a.DB.Where("name = ?", roleName).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}

	}

	// find the permission
	var perm Permission
	res = a.DB.Where("name = ?", permName).First(&perm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrPermissionNotFound
		}

	}

	// revoke the permission
	a.DB.Where("role_id = ?", role.ID).Where("permission_id = ?", perm.ID).Delete(RolePermission{})

	return nil
}

func (a *AuthorizationX) GetRoles() ([]string, error) {
	var result []string
	var roles []Role
	a.DB.Find(&roles)

	for _, role := range roles {
		result = append(result, role.Name)
	}

	return result, nil
}

func (a *AuthorizationX) GetUserRoles(userID uint) ([]string, error) {
	var result []string
	var userRoles []UserRole
	a.DB.Where("user_id = ?", userID).Find(&userRoles)

	for _, r := range userRoles {
		var role Role
		// for every user role get the role name
		res := a.DB.Where("id = ?", r.RoleID).Find(&role)
		if res.Error == nil {
			result = append(result, role.Name)
		}
	}

	return result, nil
}

func (a *AuthorizationX) GetPermissions() ([]string, error) {
	var result []string
	var perms []Permission
	a.DB.Find(&perms)

	for _, perm := range perms {
		result = append(result, perm.Name)
	}

	return result, nil
}

func (a *AuthorizationX) DeleteRole(roleName string) error {
	// find the role
	var role Role
	res := a.DB.Where("name = ?", roleName).First(&role)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrRoleNotFound
		}

	}

	// check if the role is assigned to a user
	var userRole UserRole
	res = a.DB.Where("role_id = ?", role.ID).First(&userRole)
	if res.Error == nil {
		// role is assigned
		return ErrRoleInUse
	}

	// revoke the assignment of permissions before deleting the role
	a.DB.Where("role_id = ?", role.ID).Delete(RolePermission{})

	// delete the role
	a.DB.Where("name = ?", roleName).Delete(Role{})

	return nil
}

func (a *AuthorizationX) DeletePermission(permName string) error {
	// find the permission
	var perm Permission
	res := a.DB.Where("name = ?", permName).First(&perm)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return ErrPermissionNotFound
		}

	}

	// check if the permission is assigned to a role
	var rolePermission RolePermission
	res = a.DB.Where("permission_id = ?", perm.ID).First(&rolePermission)
	if res.Error == nil {
		// role is assigned
		return ErrPermissionInUse
	}

	// delete the permission
	a.DB.Where("name = ?", permName).Delete(Permission{})

	return nil
}
