package utilities

func Int32AsLeBytes(i int32) (result []byte) {
	result = make([]byte, 4)
	left := (byte)((i >> 24) & 0x000000ff)
	leftmiddle := (byte)((i >> 16) & 0x000000ff)
	rightmiddle := (byte)((i >> 8) & 0x000000ff)
	right := (byte)((i >> 0) & 0x000000ff)
	result[3] = left
	result[2] = leftmiddle
	result[1] = rightmiddle
	result[0] = right
	return
}
