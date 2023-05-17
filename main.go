package main

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/sferawann/go-auth-jwt/auth"
)

// nantiterapkan env
var jwtKey = "SECRET_KEY"

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	//ginrouter
	r := gin.Default()

	//setup routers
	r.POST("/auth/login", loginHandler)

	userRouter := r.Group("api/v1/users")

	//middleware
	userRouter.Use(auth.AuthMiddleware(jwtKey))
	userRouter.GET("/:id/profile", profileHandler)
	//start server
	r.Run(":8080")
}

func loginHandler(c *gin.Context) {
	var user User
	if err := c.ShouldBind(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	//logic authentication(compare username dan password)
	if user.Username == "arul" && user.Password == "arul" {
		// bikin code untuk generate token
		token := jwt.New(jwt.SigningMethodHS256)

		claims := token.Claims.(jwt.MapClaims)

		claims["username"] = user.Username
		claims["exp"] = time.Now().Add(time.Minute * 1).Unix() // token akan expired dalam 1 menit

		tokenStr, err := token.SignedString(jwtKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenStr}) // jika login berhasil, dapatkan token string
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}

}

func profileHandler(c *gin.Context) {
	//ambil username dari jwt token
	claims := c.MustGet("claims").(jwt.MapClaims)
	username := claims["username"].(string)

	//seharusnya return user dr database, tp di contoh ini return username
	c.JSON(http.StatusOK, gin.H{"username": username})
}
