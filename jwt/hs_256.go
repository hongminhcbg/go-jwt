package jwt

import (
	"fmt"
	"github.com/golang-jwt/jwt"
)

type hs256Impl struct {
	secret []byte
}

func NewHs256Jwt(secret []byte) IJwt {
	return &hs256Impl{secret: secret}
}

func (x *hs256Impl) Generate(in map[string]interface{}) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(in))
	return token.SignedString(x.secret)
}

func (x *hs256Impl) Verify(token string) error {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return x.secret, nil
	})

	if err != nil {
		return err
	}
	fmt.Printf("claims = %+v\n", t.Claims)
	if t.Valid {
		return nil
	}

	return fmt.Errorf("invalid token")
}
