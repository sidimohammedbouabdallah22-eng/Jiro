package main

import "github.com/sidimohammedbouabdallah22-eng/Jiro/internal/credentials"

func secretValue(environment, path string) (string, error) {
	return credentials.Value(environment, path)
}
