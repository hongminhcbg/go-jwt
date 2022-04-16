package jwt

import (
	"crypto/rsa"
	"fmt"
	"github.com/golang-jwt/jwt"
)

type rs256Impl struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewRs256Impl(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) IJwt {
	return &rs256Impl{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

func (x *rs256Impl) Generate(in map[string]interface{}) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(in))
	return token.SignedString(x.privateKey)
}

func (x *rs256Impl) Verify(token string) error {
	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return x.publicKey, nil
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
