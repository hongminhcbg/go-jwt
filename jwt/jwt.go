package jwt

type IJwt interface {
	Generate(in map[string]interface{}) (string, error)
	Verify(token string) error
}
