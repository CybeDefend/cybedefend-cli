package logger

import (
	"fmt"
	"runtime"
	"time"

	"github.com/mattn/go-colorable"
)

// Log levels
const (
	LevelInfo    = "INFO"
	LevelWarn    = "WARN"
	LevelError   = "ERROR"
	LevelSuccess = "SUCCESS"
)

// ANSI escape codes for colors and formatting (Charm Log style)
var (
	colorReset    = "\033[0m"
	colorBlue     = "\033[34m" // For INFO: Soft Blue
	colorYellow   = "\033[33m" // For WARN: Yellow
	colorLightRed = "\033[91m" // For ERROR: Light Red (less aggressive)
	colorGreen    = "\033[32m" // For SUCCESS: Green
	bold          = "\033[1m"  // Bold text
	output        = colorable.NewColorableStdout()
)

func init() {
	// Sur Windows, les séquences ANSI nécessitent une gestion spéciale
	if runtime.GOOS == "windows" {
		output = colorable.NewColorableStdout()
	}
}

// getCurrentTime returns the current timestamp in a readable format
func getCurrentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// logMessage is a helper function to format log messages
func logMessage(level string, color string, format string, a ...interface{}) {
	timestamp := getCurrentTime()
	message := fmt.Sprintf(format, a...)
	// Apply color only to the level part
	fmt.Fprintf(output, "%s%s %s[%s]%s %s\n", timestamp, bold, color, level, colorReset, message)
}

// Info logs an informational message in blue
func Info(format string, a ...interface{}) {
	logMessage(LevelInfo, colorBlue, format, a...)
}

// Warn logs a warning message in yellow
func Warn(format string, a ...interface{}) {
	logMessage(LevelWarn, colorYellow, format, a...)
}

// Error logs an error message in light red
func Error(format string, a ...interface{}) {
	logMessage(LevelError, colorLightRed, format, a...)
}

// Success logs a success message in green
func Success(format string, a ...interface{}) {
	logMessage(LevelSuccess, colorGreen, format, a...)
}
