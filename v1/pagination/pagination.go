package pagination

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

const (
	DefaultLimit = 10
	MaximumLimit = 100
)

func getValues(orders SortOrderArray, entity any, value reflect.Value) ([]Value, error) {
	schema, err := schema.Parse(&entity, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		return nil, errors.New("failed to parse struct schema")
	}

	mapName := map[string]string{}
	for _, field := range schema.Fields {
		mapName[field.DBName] = field.Name
	}

	values := []Value{}
	for _, order := range orders {
		keys := strings.Split(order.Key, ".")
		value := value.FieldByName(mapName[keys[len(keys)-1]])
		if !value.IsValid() {
			return nil, errors.New(fmt.Sprintf("not found such field: %s", keys[len(keys)-1]))
		}

		v, err := parseValue(value.Interface())
		if err != nil {
			return nil, err
		}

		values = append(values, v)
	}

	return values, nil
}

func reverse(val *reflect.Value) {
	if val.Len() == 1 {
		return
	}

	fnc := reflect.Swapper(val.Interface())
	for i := 0; i < val.Len()/2; i++ {
		fnc(i, val.Len()-1-i)
	}
}

func getCursor(orders SortOrderArray, entities any, value reflect.Value, isBackward bool) (*Cursor, error) {
	val, err := getValues(orders, entities, value)
	if err != nil {
		return nil, err
	}

	return NewCursor(orders, isBackward, false, val)
}

func GetResult[T any](pgn Pagination, entities T) (PaginationResult, error) {
	res := PaginationResult{}

	if !pgn.IsCursor() {
		res.Limit = pgn.Limit
		res.Page = &pgn.Page

		return res, nil
	}

	if pgn.CursorEncoded == "" && !pgn.Cursor.IsEmpty() {
		pgn.CursorEncoded = pgn.Cursor.Encode()
	}

	val := reflect.ValueOf(entities)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Slice {
		return res, errors.New("expected a slice")
	}

	res.Limit = pgn.Limit
	if val.Len() == 0 {
		return res, nil
	}

	if !pgn.Cursor.IsEmpty() && val.Len() > pgn.Limit {
		val.Set(val.Slice(0, val.Len()-1))
		if pgn.Cursor != nil && pgn.Cursor.isBackward {
			reverse(&val)
		}

		next, err := getCursor(pgn.Cursor.orders, entities, val.Index(val.Len()-1), false)
		if err != nil {
			return PaginationResult{}, err
		}

		prev, err := getCursor(pgn.Cursor.orders, entities, val.Index(0), true)
		if err != nil {
			return PaginationResult{}, err
		}

		res.NextCursor = next.Encode()
		res.SelfCursor = pgn.CursorEncoded
		res.PrevCursor = prev.Encode()
		return res, err
	}

	res.SelfCursor = pgn.CursorEncoded
	if pgn.Cursor.IsEmpty() || pgn.Cursor.isBackward {
		if pgn.Cursor.IsEmpty() {
			if val.Len() <= pgn.Limit {
				return res, nil
			}

			val.Set(val.Slice(0, val.Len()-1))
		}

		next, err := getCursor(pgn.Cursor.orders, entities, val.Index(val.Len()-1), false)
		if err != nil {
			return PaginationResult{}, err
		}

		res.NextCursor = next.Encode()
	} else {
		prev, err := getCursor(pgn.Cursor.orders, entities, val.Index(0), true)
		if err != nil {
			return PaginationResult{}, err
		}

		res.PrevCursor = prev.Encode()
	}

	return res, nil
}

type PaginateOption struct {
	// UseOffset forces to use offset based pagination.
	UseOffset bool
	// UseCursor forces to use cursor based pagination.
	UseCursor bool
}

func (p *Pagination) initOffset() {
	if p.Page < 1 {
		p.Page = 1
	}

	p.Offset = p.Limit * (p.Page - 1)
	return
}

func (p *Pagination) initCursor() (err error) {
	if p.CursorEncoded != "" {
		p.Cursor, err = Decode(p.CursorEncoded)
	} else if p.Cursor == nil {
		p.Cursor = &Cursor{}
	}

	return
}

// Paginate processes the pagination provided.
func (p *Pagination) Paginate(opts ...func(*PaginateOption)) (err error) {
	option := PaginateOption{}
	for _, opt := range opts {
		opt(&option)
	}

	if p.Limit <= 0 {
		p.Limit = DefaultLimit
	}

	if p.Limit > MaximumLimit {
		p.Limit = MaximumLimit
	}

	if option.UseOffset {
		p.initOffset()
		return
	}

	if option.UseCursor {
		err = p.initCursor()
		return
	}

	if p.Page > 0 {
		p.initOffset()
		return
	}

	return p.initCursor()
}

func (p Pagination) IsCursor() bool {
	if p.Cursor != nil {
		return true
	}
	return false
}

// Query applies pagination conditions to GORM query with specified ORDER BY clause.
//
// Defaults to cursor based pagination if there is no pagination options provided.
//
//	pgn.Query(db, "created_at DESC, id DESC").Find(&users)
func (p *Pagination) Query(tx *gorm.DB, order string) *gorm.DB {
	if p.Cursor != nil {
		tx = p.Cursor.Query(tx, order).Limit(p.Limit + 1)
		return tx
	}

	if p.Page > 0 {
		return tx.Order(order).Limit(p.Limit).Offset(p.Offset)
	}

	return tx.Order(order).Limit(p.Limit + 1)
}
