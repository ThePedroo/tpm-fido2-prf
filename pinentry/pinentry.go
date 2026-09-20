package pinentry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"sync"
	"time"

	assuan "github.com/foxcpp/go-assuan/client"
	"github.com/foxcpp/go-assuan/pinentry"
)

const (
	// TimeoutU2F is the user-presence timeout for U2F (CTAP1) requests.
	// U2F clients poll roughly every 750ms and each poll extends the
	// timer, so this only needs to cover the gap between polls.
	TimeoutU2F = 2 * time.Second
	// TimeoutCTAP2 is the user-presence timeout for CTAP2 requests.
	// CTAP2 clients send a single request and wait silently (no polling),
	// so the dialog must stay up long enough for a human to respond.
	TimeoutCTAP2 = 30 * time.Second
)

func New() *Pinentry {
	return &Pinentry{}
}

type Pinentry struct {
	mu            sync.Mutex
	activeRequest *request
}

type request struct {
	timeout       time.Duration
	extendTimeout chan time.Duration

	challengeParam   [32]byte
	applicationParam [32]byte

	// subscribers holds one buffered channel per waiter sharing this
	// prompt, so every waiter observes the result (broadcast on completion).
	mu          sync.Mutex
	subscribers []chan Result
}

// subscribe registers a new waiter on the request. The returned channel is
// buffered so a waiter that stopped listening never blocks delivery.
func (r *request) subscribe() <-chan Result {
	ch := make(chan Result, 1)
	r.mu.Lock()
	r.subscribers = append(r.subscribers, ch)
	r.mu.Unlock()
	return ch
}

type Result struct {
	OK    bool
	Error error
}

func (pe *Pinentry) ConfirmPresence(prompt string, challengeParam, applicationParam [32]byte, timeout time.Duration) (<-chan Result, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if pe.activeRequest != nil {
		if challengeParam != pe.activeRequest.challengeParam || applicationParam != pe.activeRequest.applicationParam {
			return nil, errors.New("other request already in progress")
		}

		req := pe.activeRequest

		go func() {
			select {
			case req.extendTimeout <- req.timeout:
			case <-time.After(req.timeout):
			}
		}()

		return req.subscribe(), nil
	}

	pe.activeRequest = &request{
		timeout:          timeout,
		challengeParam:   challengeParam,
		applicationParam: applicationParam,
		extendTimeout:    make(chan time.Duration),
	}

	req := pe.activeRequest
	go pe.prompt(req, prompt)

	return req.subscribe(), nil
}

func (pe *Pinentry) prompt(req *request, prompt string) {
	sendResult := func(r Result) {
		req.mu.Lock()
		for _, sub := range req.subscribers {
			select {
			case sub <- r:
			default:
			}
		}
		req.mu.Unlock()

		pe.mu.Lock()
		pe.activeRequest = nil
		pe.mu.Unlock()
	}

	childCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Printf("pinentry: launching pinentry...")
	p, cmd, err := launchPinEntry(childCtx)
	if err != nil {
		log.Printf("pinentry: failed to launch: %v", err)
		sendResult(Result{
			OK:    false,
			Error: fmt.Errorf("failed to start pinentry: %w", err),
		})
		return
	}
	log.Printf("pinentry: launched successfully, cmd=%v", cmd.Args)
	defer func() {
		cancel()
		cmd.Wait()
	}()

	defer p.Shutdown()
	p.SetTitle("TPM-FIDO")
	p.SetPrompt("TPM-FIDO")
	p.SetDesc(prompt)

	promptResult := make(chan error)

	go func() {
		err := p.Confirm()
		log.Printf("pinentry Confirm() returned: %v", err)
		promptResult <- err
	}()

	timer := time.NewTimer(req.timeout)

	for {
		select {
		case err := <-promptResult:
			sendResult(Result{
				OK:    err == nil,
				Error: err,
			})
			return
		case <-timer.C:
			sendResult(Result{
				OK:    false,
				Error: errors.New("request timed out"),
			})
			return
		case d := <-req.extendTimeout:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(d)
		}
	}
}

func FindPinentryCandidates() []string {
	// Prefer Qt on Wayland as it tends to work better, then GTK/X11/fltk,
	// then curses/tty and finally generic `pinentry`.
	return []string{
		"pinentry-qt5",
		"pinentry-qt",
		"pinentry-gnome3",
		"pinentry-qt4",
		"pinentry-gtk-2",
		"pinentry-gtk",
		"pinentry-x11",
		"pinentry-fltk",
		"pinentry-curses",
		"pinentry-tty",
		"pinentry",
	}
}

func FindPinentryGUIPath() string {
	for _, candidate := range FindPinentryCandidates() {
		p, _ := exec.LookPath(candidate)
		if p != "" {
			return p
		}
	}
	return ""
}

func launchPinEntry(ctx context.Context) (*pinentry.Client, *exec.Cmd, error) {
	candidates := FindPinentryCandidates()
	var lastErr error
	for _, pinEntryCmd := range candidates {
		if p, _ := exec.LookPath(pinEntryCmd); p == "" {
			continue
		}

		cmd := exec.CommandContext(ctx, pinEntryCmd)

		stdout, err := cmd.StdoutPipe()
		if err != nil {
			lastErr = err

			continue
		}

		stdin, err := cmd.StdinPipe()
		if err != nil {
			lastErr = err

			continue
		}

		stderr, err := cmd.StderrPipe()
		if err != nil {
			/* INFO: Not fatal, so just log and continue with stderr = nil */
			log.Printf("pinentry: warning: failed to get stderr pipe for %s: %v", pinEntryCmd, err)

			stderr = nil
		}

		var stderrBuf bytes.Buffer
		if stderr != nil {
			go func() {
				io.Copy(&stderrBuf, stderr)
			}()
		}

		if err := cmd.Start(); err != nil {
			log.Printf("pinentry: failed to start %s: %v", pinEntryCmd, err)

			lastErr = err

			continue
		}

		var c pinentry.Client
		c.Session, err = assuan.Init(assuan.ReadWriteCloser{
			ReadCloser:  stdout,
			WriteCloser: stdin,
		})

		if err != nil {
			/* INFO: If stderr reports something, log it for debugging */
			stderrStr := stderrBuf.String()
			_ = cmd.Process.Kill()
			cmd.Wait()

			lastErr = fmt.Errorf("%w; stderr=%q", err, stderrStr)
			log.Printf("pinentry: %s assuan.Init failed: %v", pinEntryCmd, lastErr)

			continue
		}

		log.Printf("pinentry: launched successfully, cmd=%v", cmd.Args)

		return &c, cmd, nil
	}

	if lastErr != nil {
		return nil, nil, lastErr
	}

	return nil, nil, fmt.Errorf("no pinentry candidate found")
}
