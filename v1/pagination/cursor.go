package pagination

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"strings"
	"time"

	"gorm.io/gorm"
)

type Cursor struct {
	orders      SortOrderArray
	values      []Value
	isBackward  bool
	isInclusive bool
}

func newGCM() (cipher.AEAD, error) {
	block, err := aes.NewCipher([]byte(os.Getenv("CURSOR_KEY")))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm, nil
}

func storeInt(buf *bytes.Buffer, val int64) {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutVarint(tmp[:], val)
	binary.Write(buf, binary.BigEndian, tmp[:n])
}

func serializeString(buf *bytes.Buffer, str string) {
	binary.Write(buf, binary.BigEndian, uint16(len(str)))
	binary.Write(buf, binary.BigEndian, []byte(str))
}

func deserializeString(r *bytes.Reader) (string, error) {
	var err error
	var len uint16
	err = binary.Read(r, binary.BigEndian, &len)
	if err != nil {
		return "", err
	}

	strByte := make([]byte, len)
	err = binary.Read(r, binary.BigEndian, &strByte)
	if err != nil {
		return "", err
	}

	return string(strByte), nil
}

// Pack marshals cursor payload using binary serialization to reduce byte size
func (c Cursor) Pack() []byte {
	buff := new(bytes.Buffer)

	binary.Write(buff, binary.BigEndian, byte(len(c.orders)))
	for _, order := range c.orders {
		fnv := fnv.New32a()
		fnv.Write([]byte(order.Key))

		binary.Write(buff, binary.BigEndian, fnv.Sum32())
		binary.Write(buff, binary.BigEndian, order.Direction.Byte())
		binary.Write(buff, binary.BigEndian, order.NullOrder.Byte())
	}

	binary.Write(buff, binary.BigEndian, byte(len(c.values)))
	for _, value := range c.values {
		storeInt(buff, int64(value.K))
		switch value.K {
		case KindInt:
			storeInt(buff, int64(value.I))
		case KindBool:
			binary.Write(buff, binary.BigEndian, &value.B)
		case KindFloat:
			binary.Write(buff, binary.BigEndian, &value.F)
		case KindTime:
			storeInt(buff, int64(value.T.UnixNano()))
		case KindString:
			serializeString(buff, value.S)
		}
	}

	binary.Write(buff, binary.BigEndian, &c.isBackward)

	return buff.Bytes()
}

func Unpack(data []byte) (*Cursor, error) {
	var orderLen uint8
	var err error

	cursor := Cursor{}
	reader := bytes.NewReader(data)

	soa := SortOrderArray{}
	err = binary.Read(reader, binary.BigEndian, &orderLen)
	if err != nil {
		return nil, err
	}
	for i := 0; i < int(orderLen); i++ {
		var dir, no byte
		so := SortOrder{}
		err = binary.Read(reader, binary.BigEndian, &so.hashedKey)
		if err != nil {
			return nil, err
		}

		err = binary.Read(reader, binary.BigEndian, &dir)
		if err != nil {
			return nil, err
		}

		err = binary.Read(reader, binary.BigEndian, &no)
		if err != nil {
			return nil, err
		}

		so.Direction = ParseDirectionByte(dir)
		so.NullOrder = ParseNullOrder(no)
		soa = append(soa, so)
	}

	var valueLen uint8
	values := []Value{}
	err = binary.Read(reader, binary.BigEndian, &valueLen)
	if err != nil {
		return nil, err
	}
	for i := 0; i < int(valueLen); i++ {
		value := Value{}
		kind, _ := binary.ReadVarint(reader)
		value.K = Kind(kind)
		switch value.K {
		case KindInt:
			value.I, err = binary.ReadVarint(reader)
		case KindBool:
			err = binary.Read(reader, binary.BigEndian, &value.B)
		case KindFloat:
			err = binary.Read(reader, binary.BigEndian, &value.F)
		case KindTime:
			value.I, err = binary.ReadVarint(reader)
			value.T = time.Unix(0, value.I)
		case KindString:
			value.S, err = deserializeString(reader)
		}
		if err != nil {
			return nil, err
		}

		values = append(values, value)
	}
	err = binary.Read(reader, binary.BigEndian, &cursor.isBackward)
	if err != nil {
		return nil, err
	}

	cursor.orders, cursor.values = soa, values
	return &cursor, nil
}

// Encode encodes cursor payload into single string.
//
// Cursor is encrypted with AES-256-GCM to prevent tampering.
func (c Cursor) Encode() string {
	gcm, err := newGCM()
	if err != nil {
		return ""
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return ""
	}

	return base64.RawURLEncoding.EncodeToString(append(nonce, gcm.Seal(nil, nonce, c.Pack(), nil)...))
}

func Decode(str string) (*Cursor, error) {
	data, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}

	gcm, err := newGCM()
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("invalid data")
	}

	nonce := data[:gcm.NonceSize()]
	cipherText := data[gcm.NonceSize():]

	dec, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return Unpack(dec)
}

// NewCursor creates cursor for keyset pagination based on given sorting sequences and values.
//
// sortOrder MUST be deterministic (end with a unique column like "id"). Non-deterministic sorts will
// cause unpredictable sorting results and broken pagination.
//
// The number of args MUST match with columns in sortOrder. (e.g., 2 columns = 2 args)
//
// Usage:
//
//	// Deterministic order (non-unique order + unique order)
//	pagination.NewCursor(pagination.RawSort("created_at DESC, id DESC"), time.Now(), 10)
func NewCursor(sortOrder OrderBuilder, isBackward bool, isInclusive bool, args ...any) (*Cursor, error) {
	c := Cursor{orders: make([]SortOrder, 0), values: make([]Value, 0)}
	c.orders = sortOrder.Build()
	c.isBackward = isBackward
	c.isInclusive = isInclusive

	for _, arg := range args {
		switch v := arg.(type) {
		case []Value:
			c.values = v
		case Value:
			c.values = append(c.values, v)
		case []any:
			for _, item := range v {
				value, err := parseValue(item)
				if err != nil {
					return nil, err
				}

				c.values = append(c.values, value)
			}
		default:
			value, err := parseValue(v)
			if err != nil {
				return nil, err
			}
			c.values = append(c.values, value)
		}
	}

	if len(c.orders) != len(c.values) {
		return nil, errors.New("mismatch sort arguments")
	}

	return &c, nil
}

func (c Cursor) buildColumnString(arr []int, mapPos map[int]int, prepareStmt bool) string {
	if len(arr) == 1 {
		key := c.orders[arr[0]].Key
		if prepareStmt {
			key = "@" + key
		}

		return key
	}

	q := "("
	for _, v := range arr {
		key := c.orders[v].Key
		if prepareStmt {
			key = "@" + key
		}

		if v == arr[len(arr)-1] {
			q = q + fmt.Sprintf("%v)", key)
		} else {
			q = q + fmt.Sprintf("%v, ", key)
		}
	}

	return q
}

func (c Cursor) IsEmpty() bool {
	if c.orders == nil || c.values == nil {
		return true
	}

	return false
}

// Query builds SQL WHERE and ORDER BY conditions for keyset pagination.
//
// Usage:
//
//	cursor.Query(db).Limit(10).Find(&users)
func (c *Cursor) Query(tx *gorm.DB, order string) *gorm.DB {
	so := RawSortOrder(order).Build()
	if c.IsEmpty() {
		c.orders = so
		return tx.Order(c.orders.String())
	}

	if len(c.orders) != len(so) {
		tx.AddError(errors.New("mismatch length sort order"))
		return tx
	}

	fnv := fnv.New32a()
	for i, order := range so {
		fnv.Reset()

		fnv.Write([]byte(order.Key))
		if c.orders[i].hashedKey != fnv.Sum32() || c.orders[i].Direction != order.Direction || c.orders[i].NullOrder != order.NullOrder {
			tx.AddError(errors.New("mismatch sort order"))
			return tx
		}

		c.orders[i].Key = order.Key
		if c.isBackward {
			c.orders[i].Direction = c.orders[i].Direction.Reverse()
			c.orders[i].NullOrder = c.orders[i].NullOrder.Reverse()
		}
	}

	multi := make([][]int, 0)
	args := map[string]any{}
	for i := 0; i < len(c.orders); i++ {
		multi = append(multi, []int{i})
		for j := i + 1; j < len(c.orders); j++ {
			if (c.orders[i].Direction != c.orders[j].Direction) || (c.orders[i].IsNullable() || c.orders[j].IsNullable()) ||
				(c.values[i].K == KindNil || c.values[j].K == KindNil) {
				break
			}

			multi[len(multi)-1] = append(multi[len(multi)-1], j)
		}

		i = multi[len(multi)-1][len(multi[len(multi)-1])-1]
	}

	mapPos := map[int]int{}
	idx := 0
	for i, v := range c.values {
		if v.K == KindNil {
			continue
		}

		mapPos[i] = idx
		idx++

		args[c.orders[i].Key] = v.GetAny()
	}

	orConds := []string{}
	for i := 0; i < len(multi); i++ {
		whereConds := []string{}
		for j := 0; j < i; j++ {
			if len(multi[j]) > 1 {
				whereConds = append(whereConds, fmt.Sprintf("%s %s %s", c.buildColumnString(multi[j], mapPos, false), c.orders[multi[j][0]].Direction.GetOp(c.isInclusive), c.buildColumnString(multi[j], mapPos, true)))
				continue
			}

			// looks like a null cursor values
			if c.values[multi[j][0]].K == KindNil {
				whereConds = append(whereConds, fmt.Sprintf("%s IS NULL", c.orders[multi[j][0]].Key))
				continue
			}

			// looks like a nullable column with a cursor values
			if c.orders[multi[j][0]].IsNullable() {
				whereConds = append(whereConds, fmt.Sprintf("(%[1]s IS NULL OR %[1]s = %[2]s)", c.orders[multi[j][0]].Key, c.buildColumnString(multi[j], mapPos, true)))
				continue
			}

			whereConds = append(whereConds, fmt.Sprintf("%s = %s", c.buildColumnString(multi[j], mapPos, false), c.buildColumnString(multi[j], mapPos, true)))
		}

		end := i == len(multi)-1
		if c.orders[multi[i][0]].IsNullable() || c.values[multi[i][0]].K == KindNil {
			if c.values[multi[i][0]].K == KindNil {
				if !end {
					continue
				}

				whereConds = append(whereConds, fmt.Sprintf("%s IS NULL", c.orders[multi[i][0]].Key))
			} else {
				whereConds = append(whereConds, fmt.Sprintf("(%[1]s IS NULL OR %[1]s %s %s)", c.orders[multi[i][0]].Key, c.orders[multi[i][0]].Direction.GetOp(c.isInclusive), c.buildColumnString(multi[i], mapPos, true)))
			}
		} else {
			whereConds = append(whereConds, fmt.Sprintf("%s %s %s", c.buildColumnString(multi[i], mapPos, false), c.orders[multi[i][0]].Direction.GetOp(c.isInclusive), c.buildColumnString(multi[i], mapPos, true)))
		}

		orConds = append(orConds, "("+strings.Join(whereConds, " AND ")+")")
	}

	tx = tx.Where(fmt.Sprintf("(%s)", strings.Join(orConds, " OR ")), args).Order(c.orders.String())

	for i, _ := range c.orders {
		if c.isBackward {
			c.orders[i].Direction = c.orders[i].Direction.Reverse()
			c.orders[i].NullOrder = c.orders[i].NullOrder.Reverse()
		}
	}

	return tx
}
