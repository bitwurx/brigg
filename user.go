package main

import (
	"strings"

	"github.com/boltdb/bolt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

const (
	BoltFileName       = "data.db" // the bold database file name
	BoltUserBucketName = "user"    // the name of the bolt user bucket
	UserJWTIssuer      = "proxy"   // the issuer value of the user jwt
)

// InvalidUserCredentialsError occurs if the username or password is invalid
type InvalidUserCredentialsError struct{}

// Error returns the invalid user credential error message
func (e *InvalidUserCredentialsError) Error() string {
	return "user: invalid username or password"
}

// DuplicateUserError occurs if a duplicate user is registered
type DuplicateUserError struct{}

// Error returns the duplicate user error message
func (e *DuplicateUserError) Error() string {
	return "user: the provided username is already in use"
}

// UserClaims represents a jwt claim containing user data
type UserClaims struct {
	// Username is the name of the user
	Username string `json:"username"`
	jwt.StandardClaims
}

// User represents a user instance
type User struct {
	// Username is the name of the user
	// Password is a hash of the user's password
	// pw is the raw password the user is identified by
	Username []byte
	Password []byte
	pw       []byte
}

// Register adds the user to the local database
//
// Attempting to register an already registered username will result in a
// duplicate user error
func (u *User) Register(db *bolt.DB) (err error) {
	if u.Username == nil || u.Password == nil || u.pw == nil {
		err = &InvalidUserCredentialsError{}
		return
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BoltUserBucketName))
		v := b.Get(u.Username)
		if v != nil {
			return &DuplicateUserError{}
		}

		if err != nil {
			return err
		}

		return b.Put(u.Username, u.Password)
	})

	return
}

// Authenticate compares the provided password hash to the stored user
// password hash
//
// Providing a invalid username or an invalid password will result in an
// invalid user credential error
func (u *User) Authenticate(db *bolt.DB) (tokenString string, err error) {
	if u.Username == nil || u.Password == nil || u.pw == nil {
		err = &InvalidUserCredentialsError{}
		return
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(BoltUserBucketName))
		v := b.Get(u.Username)
		if v == nil {
			return &InvalidUserCredentialsError{}
		}

		if err := bcrypt.CompareHashAndPassword(v, u.pw); err != nil {
			return &InvalidUserCredentialsError{}
		}

		return nil
	})

	if err == nil {
		claims := UserClaims{string(u.Username), jwt.StandardClaims{
			Issuer:  UserJWTIssuer,
			Subject: nodeId.String(),
		}}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, err = token.SignedString(privateKey)
	}

	return
}

// NewUser returns a new user instance
//
// The user password hashed and stored in the Password member and the user name
// is converted to lowercase for case insensitive authentication
func NewUser(username, password []byte) (*User, error) {
	pw, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &User{[]byte(strings.ToLower(string(username))), pw, password}, nil
}

// NewUserFromJwt returns a user instance from an existing jwt
//
// The returned user instance omits the password and password hash members
func NewUserFromJWT(tokenString string) (*User, error) {
	c := &UserClaims{}
	_, err := jwt.ParseWithClaims(tokenString, c, func(t *jwt.Token) (interface{}, error) {
		return privateKey.Public(), nil
	})
	if err != nil {
		return nil, err
	}
	u := &User{Username: []byte(c.Username)}

	return u, nil
}
