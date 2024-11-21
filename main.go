package main

import (
	"a21hc3NpZ25tZW50/api"
	"a21hc3NpZ25tZW50/db/filebased"
	"a21hc3NpZ25tZW50/middleware"
	repo "a21hc3NpZ25tZW50/repository"
	"a21hc3NpZ25tZW50/service"
	"fmt"
	"time"

	_ "embed"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

type APIHandler struct {
	CategoryAPIHandler api.CategoryAPI
	TaskAPIHandler     api.TaskAPI
}

func main() {
	gin.SetMode(gin.ReleaseMode) //release

	router := gin.New()
	router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf("[%s] \"%s %s %s\"\n",
			param.TimeStamp.Format(time.RFC822),
			param.Method,
			param.Path,
			param.ErrorMessage,
		)
	}))
	router.Use(gin.Recovery())

	filebasedDb, err := filebased.InitDB()

	if err != nil {
		panic(err)
	}

	router = RunServer(router, filebasedDb)

	fmt.Println("Server is running on port 8080")
	err = router.Run(":8080")
	if err != nil {
		panic(err)
	}
}

func RunServer(gin *gin.Engine, filebasedDb *filebased.Data) *gin.Engine {
	categoryRepo := repo.NewCategoryRepo(filebasedDb)
	taskRepo := repo.NewTaskRepo(filebasedDb)

	categoryService := service.NewCategoryService(categoryRepo)
	taskService := service.NewTaskService(taskRepo)

	categoryAPIHandler := api.NewCategoryAPI(categoryService)
	taskAPIHandler := api.NewTaskAPI(taskService)

	apiHandler := APIHandler{
		CategoryAPIHandler: categoryAPIHandler,
		TaskAPIHandler:     taskAPIHandler,
	}

	// Apply Auth middleware to task routes
	task := gin.Group("/task", middleware.Auth())
	{
		task.POST("/add", apiHandler.TaskAPIHandler.AddTask)
		task.GET("/get/:id", apiHandler.TaskAPIHandler.GetTaskByID)
		task.PUT("/update/:id", apiHandler.TaskAPIHandler.UpdateTask)
		task.DELETE("/delete/:id", apiHandler.TaskAPIHandler.DeleteTask)
		task.GET("/list", apiHandler.TaskAPIHandler.GetTaskList)
		task.GET("/category/:id", apiHandler.TaskAPIHandler.GetTaskListByCategory)
	}

	// Apply Auth middleware to category routes
	category := gin.Group("/category", middleware.Auth())
	{
		category.POST("/add", apiHandler.CategoryAPIHandler.AddCategory)
		category.GET("/get/:id", apiHandler.CategoryAPIHandler.GetCategoryByID)
		category.PUT("/update/:id", apiHandler.CategoryAPIHandler.UpdateCategory)
		category.DELETE("/delete/:id", apiHandler.CategoryAPIHandler.DeleteCategory)
		category.GET("/list", apiHandler.CategoryAPIHandler.GetCategoryList)
	}

	return gin
}

