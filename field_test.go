package fp

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"math/big"
	"testing"
)

var fuz int = 1

var targetNumberOfLimb int = -1

var from = 1
var to = 8

func TestMain(m *testing.M) {
	_fuz := flag.Int("fuzz", 1, "# of iters")
	nol := flag.Int("nol", 0, "backend bit size")
	flag.Parse()
	fuz = *_fuz
	if *nol > 0 {
		targetNumberOfLimb = *nol
		if !(targetNumberOfLimb >= from && targetNumberOfLimb <= to) {
			panic(fmt.Sprintf("limb size %d not supported", targetNumberOfLimb))
		}
		from = targetNumberOfLimb
		to = targetNumberOfLimb
	}
	m.Run()
}

func randField(limbSize int) *field {
	byteSize := limbSize * 8
	pbig, err := rand.Prime(rand.Reader, 8*byteSize-1)
	if err != nil {
		panic(err)
	}
	rawpbytes := pbig.Bytes()
	pbytes := make([]byte, byteSize)
	copy(pbytes[byteSize-len(rawpbytes):], pbig.Bytes())
	f, _ := NewField(pbytes)
	return f
}

func debugBytes(a ...[]byte) {
	for _, b := range a {
		for i := (len(b) / 8) - 1; i > -1; i-- {
			fmt.Printf("0x%16.16x,\n", b[i*8:i*8+8])
		}
		fmt.Println()
	}
}

func resolveLimbSize(bitSize int) int {
	size := (bitSize / 64)
	if bitSize%64 != 0 {
		size += 1
	}
	return size
}

func randBytes(max *big.Int) []byte {
	return padBytes(randBig(max).Bytes(), resolveLimbSize(max.BitLen())*8)
}

func randBig(max *big.Int) *big.Int {
	bi, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}
	return bi
}

func BenchmarkField(t *testing.B) {
	var limbSize int
	if targetNumberOfLimb > 0 {
		limbSize = targetNumberOfLimb
	} else {
		return
	}
	field := randField(limbSize)
	if field.limbSize != limbSize {
		t.Fatalf("bad field construction")
	}
	bitSize := limbSize * 64
	a, _ := field.RandFieldElement(rand.Reader)
	b, _ := field.RandFieldElement(rand.Reader)
	c := field.NewFieldElement()
	t.Run(fmt.Sprintf("%d_Add", bitSize), func(t *testing.B) {
		for i := 0; i < t.N; i++ {
			field.Add(c, a, b)
		}
	})
	t.Run(fmt.Sprintf("%d_Double", bitSize), func(t *testing.B) {
		for i := 0; i < t.N; i++ {
			field.Double(c, a)
		}
	})
	t.Run(fmt.Sprintf("%d_Sub", bitSize), func(t *testing.B) {
		for i := 0; i < t.N; i++ {
			field.Sub(c, a, b)
		}
	})
	t.Run(fmt.Sprintf("%d_Mul", bitSize), func(t *testing.B) {
		for i := 0; i < t.N; i++ {
			field.Mul(c, a, b)
		}
	})
	t.Run(fmt.Sprintf("%d_cmp", bitSize), func(t *testing.B) {
		for i := 0; i < t.N; i++ {
			field.cmp(a, b)
		}
	})
}

func TestShift(t *testing.T) {
	two := big.NewInt(2)
	for limbSize := from; limbSize < to+1; limbSize++ {
		t.Run(fmt.Sprintf("%d_shift", limbSize*64), func(t *testing.T) {
			field := randField(limbSize)
			a, _ := field.RandFieldElement(rand.Reader)
			bi := field.ToBigNoTransform(a)
			da := field.NewFieldElement()
			field.copy(da, a)
			field.div_two(da)
			dbi := new(big.Int).Div(bi, two)
			dbi_2 := field.ToBigNoTransform(da)
			if dbi.Cmp(dbi_2) != 0 {
				t.Fatalf("bad div 2 operation")
			}
			ma := field.NewFieldElement()
			field.copy(ma, a)
			field.mul_two(ma)
			mbi := new(big.Int).Mul(bi, two)
			mbi_2 := field.ToBigNoTransform(ma)
			if mbi.Cmp(mbi_2) != 0 {
				t.Fatalf("bad Mul 2 operation")
			}
		})
	}
}

func TestCompare(t *testing.T) {
	for limbSize := from; limbSize < to+1; limbSize++ {
		t.Run(fmt.Sprintf("%d_compare", limbSize*64), func(t *testing.T) {
			field := randField(limbSize)
			if field.cmp(field.r, field.r) != 0 {
				t.Fatalf("r == r (cmp)")
			}
			if !field.Equal(field.r, field.r) {
				t.Fatalf("r == r (Equal)")
			}
			if field.Equal(field.p, field.r) {
				t.Fatalf("p != r")
			}
			if field.Equal(field.r, field.zero) {
				t.Fatalf("r != 0")
			}
			if !field.Equal(field.zero, field.zero) {
				t.Fatalf("0 == 0")
			}
			if field.cmp(field.p, field.r) != 1 {
				t.Fatalf("p > r")
			}
			if field.cmp(field.r, field.p) != -1 {
				t.Fatalf("r < p")
			}
			if is_even(field.p) {
				t.Fatalf("p is not even")
			}
		})
	}
}

func TestCopy(t *testing.T) {
	for limbSize := from; limbSize < to+1; limbSize++ {
		t.Run(fmt.Sprintf("%d_copy", limbSize*64), func(t *testing.T) {
			field := randField(limbSize)
			a, _ := field.RandFieldElement(rand.Reader)
			b := field.NewFieldElement()
			field.copy(b, a)
			if !field.Equal(a, b) {
				t.Fatalf("copy operation fails")
			}
		})
	}
}

func TestSerialization(t *testing.T) {
	for limbSize := from; limbSize < to+1; limbSize++ {
		t.Run(fmt.Sprintf("%d_serialization", limbSize*64), func(t *testing.T) {
			field := randField(limbSize)
			if field.limbSize != limbSize {
				t.Fatalf("bad field construction\n")
			}
			// demont(r) == 1
			b0 := make([]byte, field.byteSize())
			b0[len(b0)-1] = byte(1)
			b1 := field.ToBytes(field.r)
			if !bytes.Equal(b0, b1) {
				t.Fatalf("demont(r) must be Equal to 1\n")
			}
			// is a => modulus should not be valid
			_, err := field.NewFieldElementFromBytes(field.pbig.Bytes())
			if err == nil {
				t.Fatalf("a number eq or larger than modulus must not be valid")
			}
			for i := 0; i < fuz; i++ {
				field := randField(limbSize)
				if field.limbSize != limbSize {
					t.Fatalf("bad field construction")
				}
				// bytes
				b0 := randBytes(field.pbig)
				a0, err := field.NewFieldElementFromBytes(b0)
				if err != nil {
					t.Fatal(err)
				}
				b1 = field.ToBytes(a0)
				if !bytes.Equal(b0, b1) {
					t.Fatalf("bad serialization (bytes)")
				}
				// string
				s := field.ToString(a0)
				a1, err := field.NewFieldElementFromString(s)
				if err != nil {
					t.Fatal(err)
				}
				if !field.Equal(a0, a1) {
					t.Fatalf("bad serialization (str)")
				}
				// big int
				a0, err = field.NewFieldElementFromBytes(b0)
				if err != nil {
					t.Fatal(err)
				}
				bi := field.ToBig(a0)
				a1, err = field.NewFieldElementFromBig(bi)
				if err != nil {
					t.Fatal(err)
				}
				if !field.Equal(a0, a1) {
					t.Fatalf("bad serialization (big.Int)")
				}
			}
		})
	}
}

func TestAdditionCrossAgainstBigInt(t *testing.T) {
	for limbSize := from; limbSize < to+1; limbSize++ {
		t.Run(fmt.Sprintf("%d_Addition_cross", limbSize*64), func(t *testing.T) {
			for i := 0; i < fuz; i++ {
				field := randField(limbSize)
				if field.limbSize != limbSize {
					t.Fatalf("Bad field construction")
				}
				a, _ := field.RandFieldElement(rand.Reader)
				b, _ := field.RandFieldElement(rand.Reader)
				c := field.NewFieldElement()
				big_a := field.ToBig(a)
				big_b := field.ToBig(b)
				big_c := new(big.Int)
				field.Add(c, a, b)
				out_1 := field.ToBytes(c)
				out_2 := padBytes(big_c.Add(big_a, big_b).Mod(big_c, field.pbig).Bytes(), field.byteSize())
				if !bytes.Equal(out_1, out_2) {
					t.Fatalf("cross test against big.Int is not satisfied A")
				}
				field.Double(c, a)
				out_1 = field.ToBytes(c)
				out_2 = padBytes(big_c.Add(big_a, big_a).Mod(big_c, field.pbig).Bytes(), field.byteSize())
				if !bytes.Equal(out_1, out_2) {
					t.Fatalf("cross test against big.Int is not satisfied B")
				}
				field.Sub(c, a, b)
				out_1 = field.ToBytes(c)
				out_2 = padBytes(big_c.Sub(big_a, big_b).Mod(big_c, field.pbig).Bytes(), field.byteSize())
				if !bytes.Equal(out_1, out_2) {
					t.Fatalf("cross test against big.Int is not satisfied C")
				}
				field.Neg(c, a)
				out_1 = field.ToBytes(c)
				out_2 = padBytes(big_c.Neg(big_a).Mod(big_c, field.pbig).Bytes(), field.byteSize())
				if !bytes.Equal(out_1, out_2) {
					t.Fatalf("cross test against big.Int is not satisfied D")
				}
			}
		})
	}
}

func TestAdditionProperties(t *testing.T) {
	for limbSize := from; limbSize < to+1; limbSize++ {
		t.Run(fmt.Sprintf("%d_Addition_properties", limbSize*64), func(t *testing.T) {
			for i := 0; i < fuz; i++ {
				field := randField(limbSize)
				if field.limbSize != limbSize {
					t.Fatalf("bad field construction")
				}
				a, _ := field.RandFieldElement(rand.Reader)
				b, _ := field.RandFieldElement(rand.Reader)
				c_1 := field.NewFieldElement()
				c_2 := field.NewFieldElement()
				field.Add(c_1, a, field.zero)
				if !field.Equal(c_1, a) {
					t.Fatalf("a + 0 == a")
				}
				field.Sub(c_1, a, field.zero)
				if !field.Equal(c_1, a) {
					t.Fatalf("a - 0 == a")
				}
				field.Double(c_1, field.zero)
				if !field.Equal(c_1, field.zero) {
					t.Fatalf("2 * 0 == 0")
				}
				field.Neg(c_1, field.zero)
				if !field.Equal(c_1, field.zero) {
					t.Fatalf("-0 == 0")
				}
				field.Sub(c_1, field.zero, a)
				field.Neg(c_2, a)
				if !field.Equal(c_1, c_2) {
					t.Fatalf("0-a == -a")
				}
				field.Double(c_1, a)
				field.Add(c_2, a, a)
				if !field.Equal(c_1, c_2) {
					t.Fatalf("2 * a == a + a")
				}
				field.Add(c_1, a, b)
				field.Add(c_2, b, a)
				if !field.Equal(c_1, c_2) {
					t.Fatalf("a + b = b + a")
				}
				field.Sub(c_1, a, b)
				field.Sub(c_2, b, a)
				field.Neg(c_2, c_2)
				if !field.Equal(c_1, c_2) {
					t.Fatalf("a - b = - ( b - a )")
				}
				c_x, _ := field.RandFieldElement(rand.Reader)
				field.Add(c_1, a, b)
				field.Add(c_1, c_1, c_x)
				field.Add(c_2, a, c_x)
				field.Add(c_2, c_2, b)
				if !field.Equal(c_1, c_2) {
					t.Fatalf("(a + b) + c == (a + c ) + b")
				}
				field.Sub(c_1, a, b)
				field.Sub(c_1, c_1, c_x)
				field.Sub(c_2, a, c_x)
				field.Sub(c_2, c_2, b)
				if !field.Equal(c_1, c_2) {
					t.Fatalf("(a - b) - c == (a - c ) -b")
				}
			}
		})
	}
}

func TestMultiplicationCrossAgainstBigInt(t *testing.T) {
	for limbSize := from; limbSize < to+1; limbSize++ {
		t.Run(fmt.Sprintf("%d_Multiplication_cross", limbSize*64), func(t *testing.T) {
			for i := 0; i < fuz; i++ {
				field := randField(limbSize)
				if field.limbSize != limbSize {
					t.Fatalf("bad field construction")
				}
				a, _ := field.RandFieldElement(rand.Reader)
				b, _ := field.RandFieldElement(rand.Reader)
				c := field.NewFieldElement()
				big_a := field.ToBig(a)
				big_b := field.ToBig(b)
				big_c := new(big.Int)
				field.Mul(c, a, b)
				out_1 := field.ToBytes(c)
				out_2 := padBytes(big_c.Mul(big_a, big_b).Mod(big_c, field.pbig).Bytes(), field.byteSize())
				if !bytes.Equal(out_1, out_2) {
					t.Fatalf("cross test against big.Int is not satisfied")
				}
			}
		})
	}
}

func TestMultiplicationProperties(t *testing.T) {
	for limbSize := from; limbSize < to+1; limbSize++ {
		t.Run(fmt.Sprintf("%d_Multiplication_properties", limbSize*64), func(t *testing.T) {
			for i := 0; i < fuz; i++ {
				field := randField(limbSize)
				if field.limbSize != limbSize {
					t.Fatalf("bad field construction")
				}
				a, _ := field.RandFieldElement(rand.Reader)
				b, _ := field.RandFieldElement(rand.Reader)
				c_1 := field.NewFieldElement()
				c_2 := field.NewFieldElement()
				field.Mul(c_1, a, field.zero)
				if !field.Equal(c_1, field.zero) {
					t.Fatalf("a * 0 == 0")
				}
				field.Mul(c_1, a, field.one)
				if !field.Equal(c_1, a) {
					t.Fatalf("a * 1 == a")
				}
				field.Mul(c_1, a, b)
				field.Mul(c_2, b, a)
				if !field.Equal(c_1, c_2) {
					t.Fatalf("a * b == b * a")
				}
				c_x, _ := field.RandFieldElement(rand.Reader)
				field.Mul(c_1, a, b)
				field.Mul(c_1, c_1, c_x)
				field.Mul(c_2, c_x, b)
				field.Mul(c_2, c_2, a)
				if !field.Equal(c_1, c_2) {
					t.Fatalf("(a * b) * c == (a * c) * b")
				}
			}
		})
	}
}

func TestExponentiation(t *testing.T) {
	for limbSize := from; limbSize < to+1; limbSize++ {
		t.Run(fmt.Sprintf("%d_Exponention", limbSize*64), func(t *testing.T) {
			for i := 0; i < fuz; i++ {
				field := randField(limbSize)
				if field.limbSize != limbSize {
					t.Fatalf("bad field construction")
				}
				a, _ := field.RandFieldElement(rand.Reader)
				u := field.NewFieldElement()
				field.Exp(u, a, big.NewInt(0))
				if !field.Equal(u, field.one) {
					t.Fatalf("a^0 == 1")
				}
				field.Exp(u, a, big.NewInt(1))
				if !field.Equal(u, a) {
					t.Fatalf("a^1 == a")
				}
				v := field.NewFieldElement()
				field.Mul(u, a, a)
				field.Mul(u, u, u)
				field.Mul(u, u, u)
				field.Exp(v, a, big.NewInt(8))
				if !field.Equal(u, v) {
					t.Fatalf("((a^2)^2)^2 == a^8")
				}
				p := new(big.Int).SetBytes(field.pbig.Bytes())
				field.Exp(u, a, p)
				if !field.Equal(u, a) {
					t.Fatalf("a^p == a")
				}
				field.Exp(u, a, p.Sub(p, big.NewInt(1)))
				if !field.Equal(u, field.r) {
					t.Fatalf("a^(p-1) == 1")
				}
			}
		})
	}
}

func TestInversion(t *testing.T) {
	for limbSize := from; limbSize < to+1; limbSize++ {
		t.Run(fmt.Sprintf("%d_inversion", limbSize*64), func(t *testing.T) {
			for i := 0; i < fuz; i++ {
				field := randField(limbSize)
				u := field.NewFieldElement()
				field.Inverse(u, field.zero)
				if !field.Equal(u, field.zero) {
					t.Fatalf("(0^-1) == 0)")
				}
				field.Inverse(u, field.one)
				if !field.Equal(u, field.one) {
					t.Fatalf("(1^-1) == 1)")
				}
				a, _ := field.RandFieldElement(rand.Reader)
				field.Inverse(u, a)
				field.Mul(u, u, a)
				if !field.Equal(u, field.r) {
					t.Fatalf("(r*a) * r*(a^-1) == r)")
				}
				v := field.NewFieldElement()
				p := new(big.Int).Set(field.pbig)
				field.Exp(u, a, p.Sub(p, big.NewInt(2)))
				field.Inverse(v, a)
				if !field.Equal(v, u) {
					t.Fatalf("a^(p-2) == a^-1")
				}
			}
		})
	}
}
