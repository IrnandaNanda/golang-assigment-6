package repository

import (
	"a21hc3NpZ25tZW50/db/filebased"
	"a21hc3NpZ25tZW50/model"
)

type UserRepository interface {
	GetUserByEmail(email string) (model.User, error)
	CreateUser(user model.User) (model.User, error)
	GetUserTaskCategory() ([]model.UserTaskCategory, error)
}

type userRepository struct {
	filebasedDb *filebased.Data
}

func NewUserRepo(filebasedDb *filebased.Data) *userRepository {
	return &userRepository{filebasedDb}
}

func (r *userRepository) GetUserByEmail(email string) (model.User, error) {
	users, err := r.filebasedDb.GetUserByEmail(email)
	if err != nil {
		return model.User{}, err
	}

	if users.Email == email {
		return users, nil
	}

	return model.User{}, nil
}

func (r *userRepository) CreateUser(user model.User) (model.User, error) {
	createdUser, err := r.filebasedDb.CreateUser(user)
	if err != nil {
		return model.User{}, err
	}
	return createdUser, nil
}

func (r *userRepository) GetUserTaskCategory() ([]model.UserTaskCategory, error) {
	userTasks, err := r.filebasedDb.GetUserTaskCategory()
	if err != nil {
		return nil, err
	}

	return userTasks, nil
}

