package doip

import (
	"io/ioutil"
	"log"
)

// Logger interface should be implemented by the client
type Logger interface {
	Debug(v ...interface{})
	Debugf(format string, v ...interface{})
	Info(v ...interface{})
	Infof(format string, v ...interface{})
}

// NewLogger creates a new logger instance.
func NewLogger() Logger {
	return &logger{
		log0: log.New(ioutil.Discard, "INFO: ", log.Lshortfile),
	}
}

type logger struct {
	log0 *log.Logger
}

func (l *logger) Debug(v ...interface{}) {
	l.log0.Println(v...)
}

func (l *logger) Debugf(format string, v ...interface{}) {
	l.log0.Printf(format, v...)
}

func (l *logger) Info(v ...interface{}) {
	l.log0.Println(v...)
}

func (l *logger) Infof(format string, v ...interface{}) {
	l.log0.Printf(format, v...)
}
