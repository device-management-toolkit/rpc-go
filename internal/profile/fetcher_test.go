/*********************************************************************
 * Copyright (c) Intel Corporation 2026
 * SPDX-License-Identifier: Apache-2.0
 **********************************************************************/

package profile

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProfileFetcherFetchDataSendsTenantHeader(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "Bearer test-token", request.Header.Get("Authorization"))
		require.Equal(t, "tenant-a", request.Header.Get("x-tenant-id"))

		_, _ = writer.Write([]byte("profile"))
	}))
	t.Cleanup(server.Close)

	fetcher := &ProfileFetcher{TenantID: "tenant-a"}
	body, err := fetcher.fetchData(server.URL, "test-token")
	require.NoError(t, err)
	require.Equal(t, []byte("profile"), body)
}
