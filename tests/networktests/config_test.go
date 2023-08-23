package networktests

import (
	"testing"

	"github.com/jik18001/CTngV2/Gen"
)

func TestConfig(t *testing.T) {
	Gen.Generateall(4, 2, 1, 1, 7, 60, 60, "")
}
