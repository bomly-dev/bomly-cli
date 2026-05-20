package testdeps

import (
	"testing"

	jwt "github.com/dgrijalva/jwt-go"
)

func TestSyntheticBomlyReviewDependency(t *testing.T) {
	claims := jwt.MapClaims{"purpose": "bomly-review-test"}
	if claims["purpose"] != "bomly-review-test" {
		t.Fatal("unexpected claims")
	}
}
