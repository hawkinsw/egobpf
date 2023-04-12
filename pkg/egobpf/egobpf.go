package egobpf

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/hawkinsw/egobpf/v2/internal/introspect"
	"github.com/hawkinsw/egobpf/v2/pkg/hookable"
)

func getPackageName() (string, error) {
	pc, _, _, ok := runtime.Caller(1)

	if !ok {
		return "", fmt.Errorf("could not get the name of the package.")
	}

	f := runtime.FuncForPC(pc)
	if f == nil {
		return "", fmt.Errorf("could not get the name of the package.")
	}

	pkgPieces := strings.Split(f.Name(), "/")
	return strings.Join(pkgPieces[0:len(pkgPieces)-1], "/"), nil
}

func Initialize() (*hookable.Hookables, error) {
	hookables, err := introspect.FindHookableFunctions()
	if err != nil {
		return nil, err
	}

	selfPackageName, err := getPackageName()
	if err != nil {
		return nil, err
	}

	for _, hookable := range hookables.Rangeable() {
		if strings.Contains(hookable.Name(), selfPackageName) {
			continue
		}
		if err := introspect.NullifyHookable(hookable); err != nil {
			return nil, err
		}
		hookable.Write(os.Stdout)
		fmt.Println()
	}

	return &hookables, err
}
