//go:build !unix

package agent

func checkBinary(path string) error {
	_, err := statBinary(path)
	return err
}
