// Command mkico turns the SuperTransfer badge into a multi-size Windows icon.
// Pure stdlib on purpose: the build box has no image tooling installed.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
)

var sizes = []int{256, 128, 64, 48, 32, 24, 16}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: mkico <source.jpg> <out.ico>")
		os.Exit(2)
	}
	img, err := loadJPEG(os.Args[1])
	if err != nil {
		fatal(err)
	}
	icons := make([]*image.RGBA, 0, len(sizes))
	for _, s := range sizes {
		icons = append(icons, boxResize(img, s))
	}
	if err := writeICO(os.Args[2], icons); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %s (%d sizes: %v)\n", os.Args[2], len(sizes), sizes)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "mkico:", err)
	os.Exit(1)
}

func loadJPEG(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return jpeg.Decode(f)
}

// boxResize centre-crops to a square and averages each destination pixel's
// source area, which keeps the badge's thin silver ring legible at 16 px where
// a bilinear scale would smear it.
func boxResize(src image.Image, size int) *image.RGBA {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	side := w
	if h < side {
		side = h
	}
	x0 := b.Min.X + (w-side)/2
	y0 := b.Min.Y + (h-side)/2

	dst := image.NewRGBA(image.Rect(0, 0, size, size))
	scale := float64(side) / float64(size)
	for y := 0; y < size; y++ {
		sy0 := y0 + int(float64(y)*scale)
		sy1 := y0 + int(float64(y+1)*scale)
		if sy1 <= sy0 {
			sy1 = sy0 + 1
		}
		for x := 0; x < size; x++ {
			sx0 := x0 + int(float64(x)*scale)
			sx1 := x0 + int(float64(x+1)*scale)
			if sx1 <= sx0 {
				sx1 = sx0 + 1
			}
			var r, g, bl, a, n uint64
			for sy := sy0; sy < sy1; sy++ {
				for sx := sx0; sx < sx1; sx++ {
					cr, cg, cb, ca := src.At(sx, sy).RGBA()
					r, g, bl, a = r+uint64(cr), g+uint64(cg), bl+uint64(cb), a+uint64(ca)
					n++
				}
			}
			if n == 0 {
				n = 1
			}
			dst.SetRGBA(x, y, color.RGBA{uint8(r / n >> 8), uint8(g / n >> 8), uint8(bl / n >> 8), uint8(a / n >> 8)})
		}
	}
	return dst
}

// writeICO emits PNG-compressed entries, which Vista and later read natively.
func writeICO(path string, icons []*image.RGBA) error {
	pngs := make([][]byte, len(icons))
	for i, im := range icons {
		var buf bytes.Buffer
		if err := png.Encode(&buf, im); err != nil {
			return err
		}
		pngs[i] = buf.Bytes()
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	le := binary.LittleEndian
	put := func(v any) {
		if err := binary.Write(f, le, v); err != nil {
			fatal(err)
		}
	}
	put(uint16(0)) // reserved
	put(uint16(1)) // 1 = icon
	put(uint16(len(icons)))

	offset := uint32(6 + 16*len(icons))
	for i, im := range icons {
		w, h := im.Bounds().Dx(), im.Bounds().Dy()
		var bw, bh byte = byte(w), byte(h)
		if w >= 256 {
			bw, bh = 0, 0 // 0 means 256 in the ICO directory
		}
		if _, err := f.Write([]byte{bw, bh, 0, 0}); err != nil {
			return err
		}
		put(uint16(1))  // colour planes
		put(uint16(32)) // bits per pixel
		put(uint32(len(pngs[i])))
		put(offset)
		offset += uint32(len(pngs[i]))
	}
	for _, p := range pngs {
		if _, err := f.Write(p); err != nil {
			return err
		}
	}
	return nil
}
