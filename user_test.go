package main

import (
	"log"
	"os"
	"testing"

	"github.com/boltdb/bolt"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

const (
	TestBoltFileName = "test.db"
)

func TestInvalidUserCredentialsErrorMessage(t *testing.T) {
	err := &InvalidUserCredentialsError{}
	if err.Error() != "user: invalid username or password" {
		t.Fatalf("Got unexpected error for InvalidUserCredentialsError; %s", err.Error())
	}
}

func TestDuplicateUserErrorMessage(t *testing.T) {
	err := &DuplicateUserError{}
	if err.Error() != "user: the provided username is already in use" {
		t.Fatalf("Got unexpected error for DuplicateUserError; %s", err.Error())
	}
}

func TestUserRegister(t *testing.T) {
	var table = []struct {
		Username []byte
		Password []byte
		Err      error
	}{
		{[]byte("joe"), nil, &InvalidUserCredentialsError{}},
		{[]byte("joe"), []byte("dGVzdDEyMw=="), nil},
		{[]byte("Joe"), []byte("dGVzdDMyMQo="), &DuplicateUserError{}},
	}

	db, err := bolt.Open(TestBoltFileName, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(TestBoltFileName)
	err = db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucket([]byte(BoltUserBucketName))
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, tc := range table {
		u, err := NewUser(tc.Username, tc.Password)
		if err != nil {
			t.Fatal(err)
		}
		if err = u.Register(db); err != tc.Err {
			if tc.Err != nil {
				t.Fatalf("Expected error to be %s; got %s", tc.Err.Error(), err)
			} else {
				t.Fatal("Expected error to be nil")
			}
		}
	}
}

func TestUserAuthenticate(t *testing.T) {
	var table = []struct {
		Username []byte
		Password []byte
		Err      error
	}{
		{[]byte("joe"), nil, &InvalidUserCredentialsError{}},
		{[]byte("jane"), []byte("dGVzdDEyMw=="), &InvalidUserCredentialsError{}},
		{[]byte("joe"), []byte("dGVzdDEyMw=="), nil},
		{[]byte("joe"), []byte("dGVzdDMyMQo="), &InvalidUserCredentialsError{}},
	}

	db, err := bolt.Open(TestBoltFileName, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(TestBoltFileName)
	err = db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucket([]byte(BoltUserBucketName))
		b := tx.Bucket([]byte(BoltUserBucketName))

		pw, err := bcrypt.GenerateFromPassword([]byte("dGVzdDEyMw=="), bcrypt.DefaultCost)
		if err != nil {
			t.Fatal(err)
		}
		return b.Put([]byte("joe"), pw)
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, tc := range table {
		u, err := NewUser(tc.Username, tc.Password)
		if err != nil {
			t.Fatal(err)
		}
		tokenString, err := u.Authenticate(db)
		if err != tc.Err {
			if tc.Err != nil {
				t.Fatalf("Expected error to be %s; got %s", tc.Err.Error(), err)
			} else {
				t.Fatalf("Expected error to be nil; got %s", err)
			}
		}
		if tokenString != "" {
			token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
				return privateKey.Public(), nil
			})
			if err != nil {
				t.Fatal(err)
			}

			if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
				if claims.Username != "joe" {
					t.Fatal("Expected claim username to be joe")
				}
				if claims.Subject != nodeId.String() {
					t.Fatalf("Expected claim sub to be %s; got %s", nodeId.String(), claims.Subject)
				}
			} else {
				t.Fatal("Error parsing token claims")
			}
		}
	}
}

func TestNewUserFromJWT(t *testing.T) {
	db, err := bolt.Open(TestBoltFileName, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(TestBoltFileName)
	db.Update(func(tx *bolt.Tx) error {
		tx.CreateBucket([]byte(BoltUserBucketName))
		return nil
	})

	u, err := NewUser([]byte("Joe"), []byte("dGVzdDEyMw=="))
	if err != nil {
		t.Fatal(err)
	}

	if err = u.Register(db); err != nil {
		t.Fatal(err)
	}
	tokenString, err := u.Authenticate(db)
	if err != nil {
		t.Fatal(err)
	}

	u, err = NewUserFromJWT(tokenString)
	if err != nil {
		t.Fatal(err)
	}

	if string(u.Username) != "joe" {
		t.Fatalf("Expected username to be 'joe'; got %s", u.Username)
	}
}
