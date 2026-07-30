package govaluate

import (
	"sync"
	"unicode/utf8"
)

type lexerStream struct {
	sourceString string
	source       []rune
	strPosition  int
	position     int
	length       int
}

var lexerStreamPool = sync.Pool{
	New: func() interface{} {
		return new(lexerStream)
	},
}

func newLexerStream(source string) *lexerStream {
	ret := lexerStreamPool.Get().(*lexerStream)
	if ret.source == nil {
		ret.source = make([]rune, 0, len(source))
	}
	for _, character := range source {
		ret.source = append(ret.source, character)
	}
	ret.sourceString = source
	ret.position = 0
	ret.strPosition = 0
	ret.length = len(ret.source)
	return ret
}

func (this *lexerStream) readCharacter() rune {
	character := this.source[this.position]
	width := utf8.RuneLen(character)
	if character == utf8.RuneError {
		_, width = utf8.DecodeRuneInString(this.sourceString[this.strPosition:])
	}
	this.position += 1
	this.strPosition += width
	return character
}

func (this *lexerStream) rewind(amount int) {
	// A negative amount seeks forward, re-consuming runes. Decode each rune's
	// real byte width so the byte cursor stays in sync with invalid UTF-8.
	if amount < 0 {
		for i := 0; i > amount; i-- {
			if this.position >= this.length {
				break
			}
			character := this.source[this.position]
			width := utf8.RuneLen(character)
			if character == utf8.RuneError {
				_, width = utf8.DecodeRuneInString(this.sourceString[this.strPosition:])
			}
			this.position += 1
			this.strPosition += width
		}
		return
	}
	for i := 0; i < amount; i++ {
		if this.position <= 0 {
			break
		}
		character := this.source[this.position-1]
		width := utf8.RuneLen(character)
		if character == utf8.RuneError {
			_, width = utf8.DecodeLastRuneInString(this.sourceString[:this.strPosition])
		}
		this.position -= 1
		this.strPosition -= width
	}
}

func (this lexerStream) canRead() bool {
	return this.position < this.length
}

func (this *lexerStream) close() {
	this.source = this.source[:0]
	lexerStreamPool.Put(this)
}
