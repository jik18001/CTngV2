package networktests

import (
	"CTngV2/Gen"
	"testing"
)

func TestConfig(t *testing.T) {
	Gen.Generateall(4, 2, 1, 1, 7, 60, 60, "")
}
