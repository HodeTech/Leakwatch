package cmd

// Register detectors at compile time via init().
import (
	_ "github.com/cemililik/leakwatch/internal/detector/anthropic"
	_ "github.com/cemililik/leakwatch/internal/detector/aws"
	_ "github.com/cemililik/leakwatch/internal/detector/dbconn"
	_ "github.com/cemililik/leakwatch/internal/detector/generic"
	_ "github.com/cemililik/leakwatch/internal/detector/github"
	_ "github.com/cemililik/leakwatch/internal/detector/gitlab"
	_ "github.com/cemililik/leakwatch/internal/detector/jwt"
	_ "github.com/cemililik/leakwatch/internal/detector/npm"
	_ "github.com/cemililik/leakwatch/internal/detector/openai"
	_ "github.com/cemililik/leakwatch/internal/detector/privatekey"
	_ "github.com/cemililik/leakwatch/internal/detector/sendgrid"
	_ "github.com/cemililik/leakwatch/internal/detector/slack"
	_ "github.com/cemililik/leakwatch/internal/detector/stripe"
)

// Register verifiers at compile time via init().
import (
	_ "github.com/cemililik/leakwatch/internal/verifier/aws"
	_ "github.com/cemililik/leakwatch/internal/verifier/github"
	_ "github.com/cemililik/leakwatch/internal/verifier/slack"
)
