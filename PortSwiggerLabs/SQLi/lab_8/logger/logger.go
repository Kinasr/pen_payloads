package logger

import (
	"log"
	"os"
	"strings"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Blue   = "\033[34m"
	White  = "\033[37m"
	Gray   = "\033[90m"
	Orange = "\033[38;5;208m"
)

// Log levels
const (
	DebugLevel = iota
	InfoLevel
	ActionLevel
	WarningLevel
	FatalLevel
	SuccessLevel
)

type Logger struct {
	Level   int
	debug   *log.Logger
	info    *log.Logger
	action  *log.Logger
	warning *log.Logger
	fatal   *log.Logger
	success *log.Logger
}

var logger *Logger

func init() {
	logger = &Logger{
		Level:   InfoLevel,
		debug:   log.New(os.Stdout, Gray+"[◎] "+Reset, log.Ltime),
		info:    log.New(os.Stdout, White+"[◉] "+Reset, log.Ltime),
		action:  log.New(os.Stdout, Blue+"[~] "+Reset, log.Ltime),
		warning: log.New(os.Stdout, Orange+"[!] "+Reset, log.Ltime),
		fatal:   log.New(os.Stdout, Red+"[-] "+Reset, log.Ltime),
		success: log.New(os.Stdout, Green+"[+] "+Reset, log.Ltime),
	}
}

// SetLogLevel sets the log level for the logger.
func SetLogLevelS(level string) {
	SetLogLevel(toLogLevel(level))
}

func SetLogLevel(level int) {
	if level < DebugLevel || level > SuccessLevel {
		logger.warning.Println("Invalid log level. Defaulting to Info.")
		level = InfoLevel
	}
	logger.Level = level
}

// Debug logs a message at the Debug level.
func Debug(msg string) {
	Debugf(msg)
}

// Debugf logs a formatted message at the Debug level.
func Debugf(format string, args ...any) {
	if logger.Level <= DebugLevel {
		logger.debug.Printf(format+"\n", args...)
	}
}

// Info logs a message at the Info level.
func Info(msg string) {
	Infof(msg)
}

// Infof logs a formatted message at the Info level.
func Infof(format string, args ...any) {
	if logger.Level <= InfoLevel {
		logger.info.Printf(format+"\n", args...)
	}
}

// Action logs a message at the Action level.
func Action(msg string) {
	Actionf(msg)
}

// Actionf logs a formatted message at the Action level.
func Actionf(format string, args ...any) {
	if logger.Level <= ActionLevel {
		logger.action.Printf(format+"\n", args...)
	}
}

// Warning logs a message at the Warning level.
func Warning(msg string) {
	Warningf(msg)
}

// Warningf logs a formatted message at the Warning level.
func Warningf(format string, args ...any) {
	if logger.Level <= WarningLevel {
		logger.warning.Printf(format+"\n", args...)
	}
}

// Fatal logs a message at the Fatal level.
func Fatal(msg string) {
	Fatalf(msg)
}

// Fatalf logs a formatted message at the Fatal level.
func Fatalf(format string, args ...any) {
	if logger.Level <= FatalLevel {
		logger.fatal.Printf(format+"\n", args...)
	}
}

// Success logs a message at the Success level.
func Success(msg string) {
	Successf(msg)
}

// Successf logs a formatted message at the Success level.
func Successf(format string, args ...any) {
	if logger.Level <= SuccessLevel {
		logger.success.Printf(format+"\n", args...)
	}
}

// Log level from string
func toLogLevel(level string) int {
	switch strings.ToLower(level) {
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "action":
		return ActionLevel
	case "warning":
		return WarningLevel
	case "fatal":
		return FatalLevel
	case "success":
		return SuccessLevel
	default:
		return InfoLevel
	}
}
