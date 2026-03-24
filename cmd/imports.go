package cmd

// Dedektörleri derleme zamanında kaydet (init() ile).
import (
	_ "github.com/cemililik/leakwatch/internal/detector/aws"
	_ "github.com/cemililik/leakwatch/internal/detector/dbconn"
	_ "github.com/cemililik/leakwatch/internal/detector/generic"
	_ "github.com/cemililik/leakwatch/internal/detector/github"
	_ "github.com/cemililik/leakwatch/internal/detector/jwt"
	_ "github.com/cemililik/leakwatch/internal/detector/privatekey"
	_ "github.com/cemililik/leakwatch/internal/detector/slack"
	_ "github.com/cemililik/leakwatch/internal/detector/stripe"
)
