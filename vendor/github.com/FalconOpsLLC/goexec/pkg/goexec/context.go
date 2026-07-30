package goexec

type ContextOption string

const (
  ContextOptionOutputTimeout      ContextOption = "output.timeout"
  ContextOptionOutputPollInterval ContextOption = "output.pollInterval"
)
