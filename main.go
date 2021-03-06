package main

import (
	"crypto/rsa"
	"fmt"
	gojwt "github.com/golang-jwt/jwt"
	"go-jwt/jwt"
	"time"
)

var hmacSampleSecret = []byte(`fdskfkjdshjfs`)

// privateKey this is PEM format, must start with '-----BEGIN RSA PRIVATE KEY-----'
var privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIJKAIBAAKCAgEAqoVkzNL7sgHDoJujpo3XOAbjDH79xxUQXH33XJ1uBoc8xRdO
y3htYd0kwFcMXquHdM70PZmw0RGViMfM+xkw9m6eZlfgMB+HcoKrsmmemv3kBbij
Kp9deCwhcicWw6QT/2Y8fNUz9ovhsvTk0fohVmfKDlzzTzQG1QERmvCW6DEGJQ+S
y8tsQDwCKPhwn3mD6UWUQYl2yyPVX4B2aCc+i58TYEziETmGDFstuzaevkgiBZYm
YfuIjpENETkepp7eO/BePj4mDUdAxPFf+FQuvvoGVGaRNNyVHN/LG26sjRZLslJE
QeiQCl0cznFEco1kadq9e4lhoYBUdEFyuBfnDh++sYFmlsDAoCSYv+ChZXrpYah0
rvvZUuEIAfYLrlrUyeIcbwcTaKNxBvTYMiykPU/fKvtXhH/O+gcr/pkFtes90akW
xkAFQc+b2neDNZn76bR1OHfvPQkdojrscaPXKnOZQUhh/kWd6kS8K/kIbh6sDLIN
9AjDcHVpKPzzM76UWJDGCfDlbi32QjDuEmNxxMLs/nKXZUGgNTbWtuNOck+h6Gfb
EvDETG3oDdQOEsRKfaGg6VWLaDYmMh2wSl4ldXl1XcwSBEP2epVEbeoes5TfODES
K4zfXzOC8HHamwp/SQZj1fNHqufUYQUMHo1C6WV63Fe3SPXJhOUG2zhPtE8CAwEA
AQKCAgBaaTe00fjZvM24jk0KthHyhtRDf+GWeLigEbnhxSbdFz9FUMJaZ5O3W8Vs
pbrNRy0e5cviDWcOssASMb2hNQ4c2zHpGZaobU8ni9j1U8LgctU/o1H/+1dXrC5f
lBIh0RE5TT+tAG34vtoARJA+NN0QLx+W1fm7eN5WeaaX/BBHNBcJ92Ph4g2XUTnj
9zXfmFI0kMu2o+f0dR9g73/YYVZsOP/RA3Kpp1JHouBwbtlkEmLXi3D2aqNQ09+V
zi9OMNWr+ho97j3GtIzG3yP/SsMuRuqsPWWoHXyCPrY16Uxb0gJ4nd3LBD+6/vuT
CcM86XLgHTZyFblKI/yjV0A4E5RRruC7Tm4FRJKsbKuzUGLXu+XiJLGmC5CzzkZj
mQHCLliG6FJEofbbEqwXzfZKWteIpWJhIrMMTylAob1GlYiFWcP6Qh7/EMNDSCmU
e05ju9stSerdPSoDMSSW1EWX94SnXXuaN1HTc/wARqR0aUUUmrO8vUQbZN+5g+DR
grngdFLZFz4CwlRUpNu00/Yrz5/xzNV6ZFHc7Z1dFg1EBEYdNjhf373zA4eAsNcu
MSjjDkZ1c5J6AtNpfFpLwTvtxeS1aE4+9oZoi6lzCt4Ssm36m2JWRch4xTVfGftw
RN7/06/2XR0FRiIqLwwh3fkimDuXrFxoUiKateOC7qNxjlp4IQKCAQEA3SNh0mdO
uAaMXUuJxjU5oSDFOcp/TwUsbofqO1dXMkkodjsbclY6dPnYCxdCu9yJnCyidLQM
lRzo/O0JYZSG4BQfwNY4uyniNtz/ByT8g98sgF7hwE9IvXTFqN2Wvrun5raL9W/X
j3NdMZVUYkWQLSZDmZC/qrDZl9pFkje+ZJwa03FoRL1Bb+VyYFpPlq3cYG4o+mYo
cFqDK4i5mxlfiZS/0gAvdApfS8mOEaYHg9q11pmrgZ58u9deJv7O94TxM3310ALf
rc2uipHMNESSpGVwN85mq7WCZ8FGyB6xPYi4Snic+ys0pYCVVDYO/GckP3jZdvfK
UAjcNnSo57sUSwKCAQEAxWc5DqyfRg2OdtHpbGPrQ2PIDq9LMMWn6d1KVSSnbpqA
2f+VnrucYrD722qHZ864LK0XpoXjdqnREc40s8egIUjYBmtkeFC4TbXVtyHY8N7+
DrCHSFMgCMQP3ssD0dR3uCd2Yq6lYwmLI8voI1GhzFRttDLgyQX1dwRm2nwEWY/w
VnW1+W6ku5ZxVquDz4mEvkSqyOChOSoIinoW98yfhEOhwypY2kXYU03sHZdevpVq
Lv0fMxnUK1TtZi2VrJGjzEpHgPSoJt5WbWlrGZnKHNl8PJT3uzD2WcAdHx2g361+
7Tm9nejjZ486gmZeLg+qkUaNRs7mpB2KSIBWMfY1jQKCAQAEknW0TvR+s4v1Zdls
Yq9VWIMbZcdqD9ZSVrcOEQk5fe+7Og+gNo4w2vWPjSSRE8c4lmepeAuGjbl3eUMn
ZFXBjkj1yLgVjpEhx0HymN4rr9KQuOV7/2emmyJ3ElXKjcCz8XRFV9GiIqV7n/XF
rmCDvnXJWAfOdKebDyU/F631EJExa/fW6/7NXHYX7eYVXHTg/YYVX0VYxVZO8R29
SjICezPYGK7ifFBqFbm9PayMGlqGHFlCbc9wZsyIi94lmfcOtHz/lv+e7VC9hrQt
JHnPslU2oirXRAJ1OLbI7nGFryz4RTQhsUv+XAE6Y3+90jgao9oDLq5dJ0G+Un0n
hWOvAoIBAAzjg3cw0ClrwyyA4iPAlmDNCAflbBxgG2mKmErc3M286sLRDDzT9Q8A
jUEzQGoHtkC8gHnP7h0WU189PnWqiAsETY6FvoaYhqAUSkLtw9NeS+o7nmmbe9D2
tC6QxMwTekmc0f75djT0L5CDxMFhmBXWQV9tnv2hFPjTYb/MLyCF5GRQxTPnBHx3
Aylsg2uuh+tAYoJBIGWyF+KqvAsr4hJptAshHbIKs2glA1CfTIFXEhrFTh8xBYha
wDFWspoU3EP/aZHC56O6CpyUMHj4cJjXnmP6Of6P4NXVVFFuxs0z78Cfb4D67rYZ
RPG0q1uIjFN17s17vtViVGANeRNEBxUCggEBAM+nDN0M5bA2LGos+axRaOC4hrqJ
0PYeMsKUlQ3KmVn2S4NMbi8vsHwfFPJR9jsZZUx7IQWpAIy6piTjC2ds5w3k3IrA
9PsHuVJ686vgP6DM/Uk7qb6nLdn5pV8WKXDc3+C5gcOHy6SOluE3/bA4zpOHPXtH
ux5nXO/iJTtecX5Sq/8jqO7uaZY49Pk9bPHL9x4IqZasacZhY4xx867sgzlEHkuO
mwHjFgL64r6HLlhKQ1gosgrU9UIZqGaTtEge4iNVt6nzEfXOVaRgIUWIhCk+54A6
5Yn6vC0HT8pUj4NU/1qtsRjOJBm7oMNaR8G5jxVAUf+ux13ZsTbpqBrFbn0=
-----END RSA PRIVATE KEY-----
`

var publicKey = `
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAqoVkzNL7sgHDoJujpo3X
OAbjDH79xxUQXH33XJ1uBoc8xRdOy3htYd0kwFcMXquHdM70PZmw0RGViMfM+xkw
9m6eZlfgMB+HcoKrsmmemv3kBbijKp9deCwhcicWw6QT/2Y8fNUz9ovhsvTk0foh
VmfKDlzzTzQG1QERmvCW6DEGJQ+Sy8tsQDwCKPhwn3mD6UWUQYl2yyPVX4B2aCc+
i58TYEziETmGDFstuzaevkgiBZYmYfuIjpENETkepp7eO/BePj4mDUdAxPFf+FQu
vvoGVGaRNNyVHN/LG26sjRZLslJEQeiQCl0cznFEco1kadq9e4lhoYBUdEFyuBfn
Dh++sYFmlsDAoCSYv+ChZXrpYah0rvvZUuEIAfYLrlrUyeIcbwcTaKNxBvTYMiyk
PU/fKvtXhH/O+gcr/pkFtes90akWxkAFQc+b2neDNZn76bR1OHfvPQkdojrscaPX
KnOZQUhh/kWd6kS8K/kIbh6sDLIN9AjDcHVpKPzzM76UWJDGCfDlbi32QjDuEmNx
xMLs/nKXZUGgNTbWtuNOck+h6GfbEvDETG3oDdQOEsRKfaGg6VWLaDYmMh2wSl4l
dXl1XcwSBEP2epVEbeoes5TfODESK4zfXzOC8HHamwp/SQZj1fNHqufUYQUMHo1C
6WV63Fe3SPXJhOUG2zhPtE8CAwEAAQ==
-----END PUBLIC KEY-----
`

var rsaPrivateKey *rsa.PrivateKey
var rsaPublicKey *rsa.PublicKey

func init() {
	var err error
	rsaPrivateKey, err = gojwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	if err != nil {
		panic(err)
	}

	rsaPublicKey, err = gojwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
	if err != nil {
		panic(err)
	}
}

func main() {
	//jwtHs256 := jwt.NewHs256Jwt(hmacSampleSecret)
	//body := map[string]interface{}{
	//	"username": "minh",
	//	"exp":      time.Now().Unix() + 10,
	//}
	//
	//token, _ := jwtHs256.Generate(body)
	//fmt.Println(token)

	jwtRs256 := jwt.NewRs256Impl(rsaPrivateKey, rsaPublicKey)
	body := map[string]interface{}{
		"username": "minh",
		"exp":      time.Now().Unix() + 3,
	}
	token, err := jwtRs256.Generate(body)
	if err != nil {
		panic(err)
	}

	fmt.Println("token = ", token)
	err = jwtRs256.Verify(token)
	if err != nil {
		panic(err)
	}

	time.Sleep(5 * time.Second)
	err = jwtRs256.Verify(token)
	if err == nil {
		panic("token must expire")
	}
}
