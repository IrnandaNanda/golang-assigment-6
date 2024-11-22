package api

import (
	"a21hc3NpZ25tZW50/model"
	"a21hc3NpZ25tZW50/service"
	"net/http"

	"github.com/gin-gonic/gin"
)

type UserAPI interface {
	Register(c *gin.Context)
	Login(c *gin.Context)
	GetUserTaskCategory(c *gin.Context)
}

type userAPI struct {
	userService service.UserService
}

func NewUserAPI(userService service.UserService) *userAPI {
	return &userAPI{userService}
}

func (u *userAPI) Register(c *gin.Context) {
	var user model.UserRegister

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("invalid decode json"))
		return
	}

	if user.Email == "" || user.Password == "" || user.Fullname == "" {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("register data is empty"))
		return
	}

	var recordUser = model.User{
		Fullname: user.Fullname,
		Email:    user.Email,
		Password: user.Password,
	}

	recordUser, err := u.userService.Register(&recordUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusCreated, model.NewSuccessResponse("register success"))
}

func (u *userAPI) Login(c *gin.Context) {
	var user model.UserLogin

	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("invalid decode json"))
		return
	}

	if user.Email == "" || user.Password == "" {
		c.JSON(http.StatusBadRequest, model.NewErrorResponse("login data is empty"))
		return
	}

	var loginUser = model.User{
		Email:    user.Email,
		Password: user.Password,
	}

	token, err := u.userService.Login(&loginUser)
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.NewErrorResponse(err.Error()))
		return
	}

	// Respons dalam format JSON sesuai ekspektasi
	c.JSON(http.StatusOK, gin.H{
		"message": "login success",
		"token":   *token,
	})
}


func (u *userAPI) GetUserTaskCategory(c *gin.Context) {
	userTaskCategories, err := u.userService.GetUserTaskCategory()
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.NewErrorResponse(err.Error()))
		return
	}

	c.JSON(http.StatusOK, userTaskCategories)
	// TODO: answer here
}
