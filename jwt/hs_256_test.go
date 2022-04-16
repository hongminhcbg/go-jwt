package jwt

import (
	"fmt"
	"testing"
	"time"
)

var hmacSampleSecret []byte = []byte(`fdskjfkjsiejffff`)

func Test_generateAndVerify(t *testing.T) {
	jwtHs256 := NewHs256Jwt(hmacSampleSecret)
	body := map[string]interface{}{
		"username": "minh",
		"exp":      time.Now().Unix() + 5,
	}

	token, err := jwtHs256.Generate(body)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(token)

	err = jwtHs256.Verify(token)
	if err != nil {
		t.Error(err)
	}

	time.Sleep(7 * time.Second)
	err = jwtHs256.Verify(token)
	fmt.Println(err)
	if err == nil {
		t.Errorf("token must expired")
	}
}
