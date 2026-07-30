package util

import (
  "math/rand" // not crypto secure
  "regexp"
  "strings"

  "github.com/google/uuid"
)

const randHostnameCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
const randStringCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
  // Up to 15 characters; only letters, digits, and hyphens (with hyphens not at the start or end).
  randHostnameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{0,14}[a-zA-Z0-9]$`)
)

func RandomHostname() (hostname string) {
  for {
    // between 2 and 10 characters
    if hostname = RandomStringFromCharset(randHostnameCharset, rand.Intn(8)+2); randHostnameRegex.MatchString(hostname) {
      return
    }
  }
}

func Truncate(s string, n int) string {
  if len(s) <= n {
    return s
  }
  return s[:n] + "..."
}

func RandomWindowsTempFile() string {
  return `\Windows\Temp\` + strings.ToUpper(uuid.New().String())
}

func RandomString() string {
  return RandomStringFromCharset(randStringCharset, rand.Intn(10)+6)
}

func RandomStringFromCharset(charset string, length int) string {
  b := make([]byte, length)
  for i := range length {
    b[i] = charset[rand.Intn(len(charset))]
  }
  return string(b)
}
