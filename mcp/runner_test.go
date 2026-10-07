/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeRPC records the last invocation and returns canned output.
type fakeRPC struct {
	args     []string
	env      []string
	stdout   string
	stderr   string
	exitCode int
	err      error
}

func (f *fakeRPC) exec(_ context.Context, _ string, args, env []string) ([]byte, []byte, int, error) {
	f.args = args
	f.env = env

	return []byte(f.stdout), []byte(f.stderr), f.exitCode, f.err
}

func newFakeRunner(f *fakeRPC) *Runner {
	return &Runner{RPCPath: "rpc", exec: f.exec}
}

func TestRunnerRun(t *testing.T) {
	t.Run("appends --json and returns stdout JSON", func(t *testing.T) {
		f := &fakeRPC{stdout: `{"amt":"16.1.25"}` + "\n"}

		out, err := newFakeRunner(f).Run(context.Background(), time.Second, "amtinfo", "--ver")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := string(out); got != `{"amt":"16.1.25"}` {
			t.Errorf("unexpected output %s", got)
		}

		if want := []string{"amtinfo", "--ver", "--json"}; !slices.Equal(f.args, want) {
			t.Errorf("args = %v, want %v", f.args, want)
		}
	})

	t.Run("wraps non-JSON stdout", func(t *testing.T) {
		f := &fakeRPC{stdout: "done"}

		out, err := newFakeRunner(f).Run(context.Background(), time.Second, "power", "state")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := string(out); got != `{"output":"done"}` {
			t.Errorf("unexpected output %s", got)
		}
	})

	t.Run("non-zero exit returns RPCError with the logged error and a hint", func(t *testing.T) {
		f := &fakeRPC{
			exitCode: 115,
			stderr: `{"level":"info","msg":"Using configuration file"}` + "\n" +
				`{"level":"error","msg":"Error 115: DeviceNotActivated"}` + "\n",
		}

		_, err := newFakeRunner(f).Run(context.Background(), time.Second, "power", "state")

		var rpcErr *RPCError
		if !errors.As(err, &rpcErr) {
			t.Fatalf("expected RPCError, got %v", err)
		}

		if rpcErr.ExitCode != 115 || rpcErr.Message != "Error 115: DeviceNotActivated" {
			t.Errorf("unexpected error %+v", rpcErr)
		}

		if !strings.Contains(err.Error(), "not activated") {
			t.Errorf("expected hint in %q", err.Error())
		}
	})

	t.Run("process start failure", func(t *testing.T) {
		f := &fakeRPC{err: errors.New("file not found")}

		if _, err := newFakeRunner(f).Run(context.Background(), time.Second, "version"); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestErrorMessageFallsBackToRawText(t *testing.T) {
	if got := errorMessage([]byte("  plain failure \n")); got != "plain failure" {
		t.Errorf("got %q", got)
	}

	if got := errorMessage(nil); got != "no error output" {
		t.Errorf("got %q", got)
	}
}
