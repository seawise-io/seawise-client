package accesslog

// pause stalls the writer until resume, to fill the queue in tests.
func (l *Log) pause() {
	ch := make(chan struct{})
	l.reqs <- func() { <-ch }
	resumeCh = ch
}

func (l *Log) resume() { close(resumeCh) }

var resumeCh chan struct{}
