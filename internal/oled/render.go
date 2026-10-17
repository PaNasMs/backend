package oled

import "strings"

var glyphs = map[rune][5]byte{
	' ': {0, 0, 0, 0, 0}, '-': {8, 8, 8, 8, 8}, '.': {0, 96, 96, 0, 0}, ':': {0, 54, 54, 0, 0}, '_': {64, 64, 64, 64, 64},
	'0': {62, 81, 73, 69, 62}, '1': {0, 66, 127, 64, 0}, '2': {66, 97, 81, 73, 70}, '3': {33, 65, 69, 75, 49},
	'4': {24, 20, 18, 127, 16}, '5': {39, 69, 69, 69, 57}, '6': {60, 74, 73, 73, 48}, '7': {1, 113, 9, 5, 3},
	'8': {54, 73, 73, 73, 54}, '9': {6, 73, 73, 41, 30},
	'A': {126, 17, 17, 17, 126}, 'B': {127, 73, 73, 73, 54}, 'C': {62, 65, 65, 65, 34}, 'D': {127, 65, 65, 34, 28},
	'E': {127, 73, 73, 73, 65}, 'F': {127, 9, 9, 9, 1}, 'G': {62, 65, 73, 73, 122}, 'H': {127, 8, 8, 8, 127},
	'I': {0, 65, 127, 65, 0}, 'J': {32, 64, 65, 63, 1}, 'K': {127, 8, 20, 34, 65}, 'L': {127, 64, 64, 64, 64},
	'M': {127, 2, 12, 2, 127}, 'N': {127, 4, 8, 16, 127}, 'O': {62, 65, 65, 65, 62}, 'P': {127, 9, 9, 9, 6},
	'Q': {62, 65, 81, 33, 94}, 'R': {127, 9, 25, 41, 70}, 'S': {70, 73, 73, 73, 49}, 'T': {1, 1, 127, 1, 1},
	'U': {63, 64, 64, 64, 63}, 'V': {31, 32, 64, 32, 31}, 'W': {63, 64, 56, 64, 63}, 'X': {99, 20, 8, 20, 99},
	'Y': {7, 8, 112, 8, 7}, 'Z': {97, 81, 73, 69, 67}, '?': {2, 1, 81, 9, 6},
}

type Text struct {
	Value       string
	X, Y, Scale int
}

func Render(lines []string, rotation, shift int) [1024]byte {
	var scene []Text
	for row, line := range lines {
		if row >= 5 {
			break
		}
		scene = append(scene, Text{short(line, 20), 2, 2 + row*12, 1})
	}
	return RenderScene(scene, rotation, shift)
}

func RenderScene(scene []Text, rotation, shift int) [1024]byte {
	var frame [1024]byte
	for _, text := range scene {
		for column, char := range []rune(strings.ToUpper(text.Value)) {
			glyph, ok := glyphs[char]
			if !ok {
				glyph = glyphs['?']
			}
			for x, bits := range glyph {
				for y := 0; y < 7; y++ {
					if bits&(1<<y) == 0 {
						continue
					}
					for dx := 0; dx < text.Scale; dx++ {
						for dy := 0; dy < text.Scale; dy++ {
							px, py := text.X+shift+(column*6+x)*text.Scale+dx, text.Y+shift+y*text.Scale+dy
							if px < 2 || px > 125 || py < 2 || py > 61 {
								continue
							}
							if rotation == 180 {
								px, py = 127-px, 63-py
							}
							frame[py/8*128+px] |= 1 << uint(py%8)
						}
					}
				}
			}
		}
	}
	return frame
}
