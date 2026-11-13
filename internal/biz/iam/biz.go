package iam

// Biz aggregates all IAM use cases for unified dependency injection.
type Biz struct {
	User   *UserUseCase
	Role   *RoleUseCase
	Menu   *MenuUseCase
	Button *ButtonUseCase
	Api    *ApiUseCase
	Auth   *AuthUseCase
}

// NewBiz creates a new Biz container.
func NewBiz(
	user *UserUseCase,
	role *RoleUseCase,
	menu *MenuUseCase,
	button *ButtonUseCase,
	api *ApiUseCase,
	auth *AuthUseCase,
) *Biz {
	if user != nil && auth != nil {
		user.SetAuthUseCase(auth)
	}
	return &Biz{
		User:   user,
		Role:   role,
		Menu:   menu,
		Button: button,
		Api:    api,
		Auth:   auth,
	}
}
