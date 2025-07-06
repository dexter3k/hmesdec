package main

import (
	"encoding/binary"
	"unicode/utf16"
	"fmt"
	"os"
	"io"

	"github.com/davecgh/go-spew/spew"
)

type BytecodeOptions uint8

type BytecodeFileHeader struct {
	Magic               uint64
	Version             uint32
	SourceHash          [20]uint8
	FileLength          uint32
	GlobalCodeIndex     uint32
	FunctionCount       uint32
	StringKindCount     uint32
	IdentifierCount     uint32
	StringCount         uint32
	OverflowStringCount uint32
	StringStorageSize   uint32
	BigIntCount         uint32
	BigIntStorageSize   uint32
	RegExpCount         uint32
	RegExpStorageSize   uint32
	ArrayBufferSize     uint32
	ObjKeyBufferSize    uint32
	ObjValueBufferSize  uint32
	SegmentID           uint32
	CjsModuleCount      uint32
	FunctionSourceCount uint32
	DebugInfoOffset     uint32
	Options             BytecodeOptions
	Padding             [19]uint8
}

type FunctionHeader struct {
	Offset                 uint32
	ParamCount             uint32
	BytecodeSizeInBytes    uint32
	FunctionName           uint32
	InfoOffset             uint32
	FrameSize              uint32
	EnvironmentSize        uint32
	HighestReadCacheIndex  uint8
	HighestWriteCacheIndex uint8
	Flags                  uint8
}

type Bundle struct {
	Functions      []*Function
	Strings        []string
	Regexp         [][]byte
	ArrayBuffer    []byte
	ObjKeyBuffer   []byte
	ObjValueBuffer []byte
}

type Function struct {
	Header     FunctionHeader
	Code       []byte
	Exceptions []ExceptionInfo
}

type ExceptionInfo struct {
	Start  uint32
	End    uint32
	Target uint32
}

func parseUtf16(d []byte) string {
	points := make([]uint16, len(d) / 2)
	for i := 0; i < len(points); i++ {
		points[i] = (uint16(d[i * 2 + 1]) << 8) | uint16(d[i * 2 + 0])
	}
	return string(utf16.Decode(points))
}

func parseBundle(r io.ReadSeeker) *Bundle {
	var header BytecodeFileHeader
	check(binary.Read(r, binary.LittleEndian, &header))
	spew.Dump(header)

	bundle := &Bundle{}

	for i := uint32(0); i < header.FunctionCount; i++ {
		var words [4]uint32
		check(binary.Read(r, binary.LittleEndian, &words))

		funcHeader := FunctionHeader{
			Offset:                 words[0] & 0x01ffffff,
			ParamCount:             words[0] >> 25,
			BytecodeSizeInBytes:    words[1] & 0x7fff,
			FunctionName:           words[1] >> 15,
			InfoOffset:             words[2] & 0x01ffffff,
			FrameSize:              words[2] >> 25,
			EnvironmentSize:        words[3] & 0xff,
			HighestReadCacheIndex:  uint8(words[3] >> 8),
			HighestWriteCacheIndex: uint8(words[3] >> 16),
			Flags:                  uint8(words[3] >> 24),
		}
		if ((funcHeader.Flags >> 5) & 0x1) != 0 {
			// Overflow
			offset := (funcHeader.InfoOffset << 16) | funcHeader.Offset

			savedOffset, _ := r.Seek(0, io.SeekCurrent)
			_, err := r.Seek(int64(offset), io.SeekStart)
			check(err)

			check(binary.Read(r, binary.LittleEndian, &funcHeader))
			funcHeader.InfoOffset += 32 // uhh, skip what we already know?

			_, err = r.Seek(savedOffset, io.SeekStart)
			check(err)
		}

		savedOffset, _ := r.Seek(0, io.SeekCurrent)
		_, err := r.Seek(int64(funcHeader.Offset), io.SeekStart)
		check(err)

		code := make([]byte, funcHeader.BytecodeSizeInBytes)
		check(binary.Read(r, binary.LittleEndian, code))

		function := &Function{
			Header: funcHeader,
			Code:   code,
		}

		if (funcHeader.Flags & 0x08) != 0 {
			_, err = r.Seek(int64(funcHeader.InfoOffset), io.SeekStart)
			check(err)

			var count uint32
			check(binary.Read(r, binary.LittleEndian, &count))

			function.Exceptions = make([]ExceptionInfo, count)
			check(binary.Read(r, binary.LittleEndian, function.Exceptions))
		}

		r.Seek(savedOffset, io.SeekStart)

		bundle.Functions = append(bundle.Functions, function)
	}

	for i := uint32(0); i < header.StringKindCount; i++ {
		var kind uint32
		check(binary.Read(r, binary.LittleEndian, &kind))
	}

	for i := uint32(0); i < header.IdentifierCount; i++ {
		var identifierHash uint32
		check(binary.Read(r, binary.LittleEndian, &identifierHash))
	}

	// Uhm, read string storage first
	savedOffset, _ := r.Seek(0, io.SeekCurrent)
	_, err := r.Seek(int64(header.StringCount) * 4 + int64(header.OverflowStringCount) * 4 * 2, io.SeekCurrent)
	check(err)
	stringStorage := make([]byte, header.StringStorageSize)
	check(binary.Read(r, binary.LittleEndian, stringStorage))
	r.Seek(savedOffset, io.SeekStart)

	// Then read overflown strings
	_, err = r.Seek(int64(header.StringCount) * 4, io.SeekCurrent)
	check(err)
	overflownOffsets := make([]uint32, 0, header.OverflowStringCount)
	overflownLengths := make([]uint32, 0, header.OverflowStringCount)
	for i := uint32(0); i < header.OverflowStringCount; i++ {
		var offset, length uint32
		check(binary.Read(r, binary.LittleEndian, &offset))
		check(binary.Read(r, binary.LittleEndian, &length))
		overflownOffsets = append(overflownOffsets, offset)
		overflownLengths = append(overflownLengths, length)
	}
	r.Seek(savedOffset, io.SeekStart)

	// And then we can parse the table..
	for i := uint32(0); i < header.StringCount; i++ {
		var word uint32
		check(binary.Read(r, binary.LittleEndian, &word))

		isUtf16 := (word & 1) != 0
		word >>= 1
		offset := word & 0x7fffff
		length := word >> 23

		if length == 0xff {
			length = overflownLengths[offset]
			offset = overflownOffsets[offset]
		}

		if !isUtf16 {
			bundle.Strings = append(bundle.Strings, string(stringStorage[offset:][:length]))
		} else {
			bundle.Strings = append(bundle.Strings, parseUtf16(stringStorage[offset:][:length * 2]))
		}
	}

	r.Seek(int64(header.OverflowStringCount) * 4 * 2 + int64(header.StringStorageSize), io.SeekCurrent)
	if header.StringStorageSize % 4 != 0 {
		_, err := r.Seek(int64(4 - header.StringStorageSize % 4), io.SeekCurrent)
		check(err)
	}

	arrayBuffer := make([]byte, header.ArrayBufferSize)
	check(binary.Read(r, binary.LittleEndian, arrayBuffer))
	if header.ArrayBufferSize % 4 != 0 {
		_, err := r.Seek(int64(4 - header.ArrayBufferSize % 4), io.SeekCurrent)
		check(err)
	}

	objKeyBuffer := make([]byte, header.ObjKeyBufferSize)
	check(binary.Read(r, binary.LittleEndian, objKeyBuffer))
	if header.ObjKeyBufferSize % 4 != 0 {
		_, err := r.Seek(int64(4 - header.ObjKeyBufferSize % 4), io.SeekCurrent)
		check(err)
	}

	objValueBuffer := make([]byte, header.ObjValueBufferSize)
	check(binary.Read(r, binary.LittleEndian, objValueBuffer))
	if header.ObjValueBufferSize % 4 != 0 {
		_, err := r.Seek(int64(4 - header.ObjValueBufferSize % 4), io.SeekCurrent)
		check(err)
	}

	// big int table
	for i := uint32(0); i < header.BigIntCount; i++ {
		panic("not implemented")
	}

	// big int storage
	for i := uint32(0); i < header.BigIntStorageSize; i++ {
		panic("not implemented")
	}

	// regexp table
	for i := uint32(0); i < header.RegExpCount; i++ {
		var offset, length uint32
		check(binary.Read(r, binary.LittleEndian, &offset))
		check(binary.Read(r, binary.LittleEndian, &length))
	}

	// regexp storage
	regexpStorage := make([]byte, header.RegExpStorageSize)
	check(binary.Read(r, binary.LittleEndian, regexpStorage))
	if header.RegExpStorageSize % 4 != 0 {
		_, err := r.Seek(int64(4 - header.RegExpStorageSize % 4), io.SeekCurrent)
		check(err)
	}

	// cjs module table
	for i := uint32(0); i < header.CjsModuleCount; i++ {
		panic("not implemented")
	}

	// func source table
	for i := uint32(0); i < header.FunctionSourceCount; i++ {
		var offset, length uint32
		check(binary.Read(r, binary.LittleEndian, &offset))
		check(binary.Read(r, binary.LittleEndian, &length))
	}

	return bundle
}

func main() {
	f, err := os.Open(os.Args[1])
	check(err)
	defer f.Close()

	bundle := parseBundle(f)

	fmt.Printf("%d strings\n", len(bundle.Strings))
	fmt.Printf("%d functions\n", len(bundle.Functions))

	for i := 0; i < len(bundle.Functions); i++ {
		// => [Function #0 "global" of 142230 bytes]: 1 params, frame size=21, env size=0, read index sz=15, write index sz=9, strict=0, exc handler=1, debug info=0  @ offset 0x00260a5c
  		// [Exception handlers: [start=0xcf, end=0x11c, target=0x11e] ]

  		f := bundle.Functions[i]
		fmt.Printf("Function %d, %q, %d bytes: %d params, frame=%d, env=%d, read=%d, write=%d, strict=%v, offset=%08x\n",
			i,
			bundle.Strings[f.Header.FunctionName],
			len(f.Code),
			f.Header.ParamCount,
			f.Header.FrameSize,
			f.Header.EnvironmentSize,
			f.Header.HighestReadCacheIndex,
			f.Header.HighestWriteCacheIndex,
			(f.Header.Flags & 4) != 0,
			f.Header.Offset,
		)

		for i, ex := range f.Exceptions {
			fmt.Printf(" - try %d [%08x-%08x], catch on %08x\n", i, ex.Start, ex.End, ex.Target)
		}

		fmt.Printf("Code:\n")
		var pc uint32
		u8 := func() uint8 {
			pc++
			return f.Code[pc - 1]
		}
		u16 := func() uint16 {
			pc += 2
			return binary.LittleEndian.Uint16(f.Code[pc - 2:][:2])
		}
		u32 := func() uint32 {
			pc += 4
			return binary.LittleEndian.Uint32(f.Code[pc - 4:][:4])
		}
		for pc < uint32(len(f.Code)) {
			opOffset := pc
			fmt.Printf("%06x: ", opOffset)
			op := u8()

			switch op {
			// 0x00: op_unreachable
			// 0x01: op_new_object_with_buffer
			// 0x02: op_new_object_with_buffer_long
			case 0x03: // op_new_object(u8_reg)
				v1 := u8()
				fmt.Printf("r%d = {}\n", v1)
			// 0x04: op_new_object_with_parent
			case 0x05: // op_new_array_with_buffer(reg, u16, u16, u16)
				v1 := u8()
				v2 := u16()
				v3 := u16()
				v4 := u16()
				fmt.Printf("r%d = new_array_with_buffer(size_hint=%d, elements=%d, index=%d)\n", v1, v2, v3, v4)
			// 0x06: op_new_array_with_buffer_long
			case 0x07: // op_new_array
				v1 := u8()
				v2 := u16()
				fmt.Printf("r%d = new Array(%d)\n", v1, v2)
			case 0x08: // op_mov(u8_reg, u8_reg)
				v1 := u8()
				v2 := u8()
				fmt.Printf("r%d = r%d\n", v1, v2)
			// 0x09: op_mov_long
			case 0x0a: // op_negate(u8_reg, u8_reg)
				v1 := u8()
				v2 := u8()
				fmt.Printf("r%d = -r%d\n", v1, v2)
			case 0x0b: // op_boolean_not(u8_reg, u8_reg)
				v1 := u8()
				v2 := u8()
				fmt.Printf("r%d = !r%d\n", v1, v2)
			case 0x0c: // op_bitwise_not(u8_reg, u8_reg)
				v1 := u8()
				v2 := u8()
				fmt.Printf("r%d = ~r%d\n", v1, v2)
			case 0x0d: // op_typeof(u8_reg, u8_reg)
				v1 := u8()
				v2 := u8()
				fmt.Printf("r%d = typeof r%d\n", v1, v2)

			case 0x29: // op_get_environment(reg, u8)
				v1 := u8()
				v2 := u8()
				fmt.Printf("r%d = environment(%d)\n", v1, v2)
			case 0x2a: // op_store_to_environment(reg, u8, reg)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				fmt.Printf("environment(r%d, %d) = r%d\n", v1, v2, v3)
			case 0x2c: // op_store_np_to_environment(reg, u8, reg)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				fmt.Printf("environment(r%d, %d) = r%d // non-pointer\n", v1, v2, v3)
			case 0x2e: // op_load_from_environment(reg, reg, u8)
			case 0x30: // op_get_global_obj(u8_reg)
				v1 := u8()
				fmt.Printf("r%d = globalThis\n", v1)
			case 0x32: // op_create_environment(u8_reg)
				v1 := u8()
				fmt.Printf("r%d = op_create_environment\n", v1)
			case 0x34: // op_declare_global_var(u32_string)
				v1 := u32()
				fmt.Printf("op_declare_global_var %q\n", bundle.Strings[v1])
			case 0x36: // op_get_by_id(u8_reg, u8_reg, u8, u8)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				v4 := u8()
				fmt.Printf("r%d = r%d[%q] // cache=%d\n", v1, v2, bundle.Strings[v4], v3)
			case 0x37: // op_get_by_id(u8_reg, u8_reg, u8, u16)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				v4 := u16()
				fmt.Printf("r%d = r%d[%q] // cache=%d\n", v1, v2, bundle.Strings[v4], v3)
			case 0x39: // op_try_get_by_id(u8_reg, u8_reg, u8, u16)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				v4 := u16()
				fmt.Printf("r%d = r%d[%q] // cache=%d\n", v1, v2, bundle.Strings[v4], v3)
			case 0x3b: // op_put_by_id(u8_reg, u8_reg, u8, u16)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				v4 := u16()
				fmt.Printf("r%d[%q] = r%d // cache=%d\n", v1, bundle.Strings[v4], v2, v3)
			case 0x4a: // op_put_by_val(reg, reg, reg)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				fmt.Printf("r%d[r%d] = r%d\n", v1, v2, v3)
			case 0x50: // op_construct(u8_reg, u8_reg, u8)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				fmt.Printf("r%d = construct(closure=r%d, %d args)\n", v1, v2, v3)
			case 0x51: // op_call1(u8_reg, u8_reg, u8_reg)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				fmt.Printf("r%d = r%d.bind(r%d)()\n", v1, v2, v3)
			case 0x53: // op_call2(u8_reg, u8_reg, u8_reg, reg)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				v4 := u8()
				fmt.Printf("r%d = r%d.bind(r%d)(r%d)\n", v1, v2, v3, v4)
			case 0x54: // op_call3(u8_reg, u8_reg, u8_reg, reg, reg)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				v4 := u8()
				v5 := u8()
				fmt.Printf("r%d = r%d.bind(r%d)(r%d, r%d)\n", v1, v2, v3, v4, v5)
			case 0x55: // op_call4(u8_reg, u8_reg, u8_reg, reg, reg, reg)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				v4 := u8()
				v5 := u8()
				v6 := u8()
				fmt.Printf("r%d = r%d.bind(r%d)(r%d, r%d, r%d)\n", v1, v2, v3, v4, v5, v6)
			case 0x5d: // op_catch(reg)
				v1 := u8()
				fmt.Printf("catch(r%d)\n", v1)
			case 0x5c: // op_ret(reg)
				v1 := u8()
				fmt.Printf("return r%d\n", v1)
			case 0x64: // op_create_closure(reg, reg, u16)
				v1 := u8()
				v2 := u8()
				v3 := u16()
				fmt.Printf("r%d = closure(r%d, %d)\n", v1, v2, v3)
			case 0x6a: // op_create_this(u8_reg, u8_reg, u8_reg)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				fmt.Printf("r%d = Object.create(r%d, {constructor: {value: r%d}})\n", v1, v2, v3)
			case 0x6b: // op_select_object(reg, reg, reg)
				v1 := u8()
				v2 := u8()
				v3 := u8()
				fmt.Printf("r%d = r%d instanceof Object ? r%d : r%d\n", v1, v3, v3, v2)
			case 0x6c: // op_load_param(reg, u8)
				v1 := u8()
				v2 := u8()
				if v2 == 0 {
					fmt.Printf("r%d = this\n", v1)
				} else {
					fmt.Printf("r%d = a%d\n", v1, v2 - 1)
				}
			case 0x6e: // op_load_const_u8(reg, u8)
				v1 := u8()
				v2 := u8()
				fmt.Printf("r%d = const[%d]\n", v1, v2)
			case 0x6f: // op_load_const_u32(reg, u32)
				v1 := u8()
				v2 := u32()
				fmt.Printf("r%d = const[%d]\n", v1, v2)
			case 0x73: // op_load_const_string(u8_reg, u16)
				v1 := u8()
				v2 := u16()
				fmt.Printf("r%d = %q\n", v1, bundle.Strings[v2])
			case 0x74: // op_load_const_string(u8_reg, u32)
				v1 := u8()
				v2 := u32()
				fmt.Printf("r%d = %q\n", v1, bundle.Strings[v2])
			case 0x76: // op_load_const_undefined(u8_reg)
				v1 := u8()
				fmt.Printf("r%d = undefined\n", v1)
			case 0x77: // op_load_const_null(u8_reg)
				v1 := u8()
				fmt.Printf("r%d = null\n", v1)
			case 0x78: // op_load_const_true(u8_reg)
				v1 := u8()
				fmt.Printf("r%d = true\n", v1)
			case 0x79: // op_load_const_false(u8_reg)
				v1 := u8()
				fmt.Printf("r%d = false\n", v1)
			case 0x7a: // op_load_const_zero(u8_reg)
				v1 := u8()
				fmt.Printf("r%d = 0\n", v1)
			case 0x7b: // op_coerce_this_ns(u8_reg, u8_reg)
				v1 := u8()
				v2 := u8()
				fmt.Printf("r%d = coerce_to_object(r%d)\n", v1, v2)
			case 0x7c: // op_load_this_ns(u8_reg)
				v1 := u8()
				fmt.Printf("r%d = this\n", v1)
			case 0x8e: // op_jmp(i8)
				v1 := int8(u8())
				target := opOffset + uint32(int32(v1))
				fmt.Printf("goto %06x\n", target)
			case 0x90: // op_jmp_true(i8, u8_reg)
				v1 := int8(u8())
				v2 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d) goto %06x\n", v2, target)
			case 0x92: // op_jmp_false(i8, u8_reg)
				v1 := int8(u8())
				v2 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (!r%d) goto %06x\n", v2, target)
			case 0x98: // op_jump_less
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0x9a: // op_jump_not_less
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0x9c: // op_jump_less_number
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0x9e: // op_jump_not_less_number
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0xa0: // op_jump_less_equal
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0xa2: // op_jump_not_less_equal
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0xa4: // op_jump_less_equal_number
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0xa6: // op_jump_not_less_equal_number
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0xa8: // op_jump_greater
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0xaa: // op_jump_not_greater
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0xac: // op_jump_greater_number
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0xae: // op_jump_not_greater_number
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0xb0: // op_jump_greater_equal
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0xb2: // op_jump_not_greater_equal
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0xb4: // op_jump_greater_equal_number
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0xb6: // op_jump_not_greater_equal_number
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d ? r%d) goto %06x\n", v2, v3, target)
			case 0xb8: // op_jump_equal
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d == r%d) goto %06x\n", v2, v3, target)
			case 0xba: // op_jump_not_equal
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d != r%d) goto %06x\n", v2, v3, target)
			case 0xbc: // op_jump_strict_equal
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d === r%d) goto %06x\n", v2, v3, target)
			case 0xbe: // op_jump_strict_not_equal
				v1 := int8(u8())
				v2 := u8()
				v3 := u8()
				target := opOffset + uint32(int32(v1))
				fmt.Printf("if (r%d !== r%d) goto %06x\n", v2, v3, target)
			default:
				panic(fmt.Errorf("Unknown bytecode: %02x. Bytes: %02x", op, f.Code[:16]))
			}
		}
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
