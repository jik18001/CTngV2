package util

// Terminal colors. Use by adding the color to the beginning of a string.
// add RESET after the string to reset the color: otherwise all text will remain this color
// in future prints.
const (
	RED    = "\x1b[31m"
	GREEN  = "\x1b[32m"
	YELLOW = "\x1b[33m"
	BLUE   = "\x1b[34m"
	RESET  = "\x1b[0m"
)

type OutOfBounds struct{}

func (e *OutOfBounds) Error() string {
	return "Index Out of Bounds"
}
