// Package util provides shared helper functions used across the identity service.
package util

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	httpserver "goauth/services/identity-service/internal/http"
)

// Pagination extracts page and page_size query parameters with safe defaults (1-100).
func Pagination(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.Query("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(c.Query("page_size"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return page, pageSize
}

// ParseInt64Param parses a URL path parameter as int64 and writes a 400 error on failure.
func ParseInt64Param(c *gin.Context, name string) (int64, error) {
	value, err := strconv.ParseInt(c.Param(name), 10, 64)
	if err != nil {
		httpserver.Error(c, http.StatusBadRequest, "invalid "+name)
		return 0, err
	}
	return value, nil
}
