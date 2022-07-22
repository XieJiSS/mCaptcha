package mcaptcha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type VerifyOpts struct {
	Secret      string `json:"secret"`
	Sitekey     string `json:"key"` //nolint:tagliatelle // `Sitekey` is the correct naming, but API expects `key`.
	Token       string `json:"token"`
	InstanceURL string `json:"-"`
}

func (opts *VerifyOpts) GetOpts() (io.Reader, error) {
	if opts.Secret == "" {
		return nil, ErrMissingSecret
	}
	if opts.Sitekey == "" {
		return nil, ErrMissingSitekey
	}
	if opts.Token == "" {
		return nil, ErrMissingToken
	}

	body, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal options: %w", err)
	}

	return bytes.NewReader(body), nil
}

type VerifyResponse struct {
	Valid bool `json:"valid"`
}

func Verify(ctx context.Context, opts *VerifyOpts) (bool, error) {
	body, err := opts.GetOpts()
	if err != nil {
		return false, err
	}

	url := strings.TrimSuffix(opts.InstanceURL, "/")

	req, err := http.NewRequestWithContext(ctx, "POST", url+"/api/v1/pow/siteverify", body)
	if err != nil {
		return false, fmt.Errorf("couldn't create a new request: %w", err)
	}

	defer req.Body.Close()

	var responseStruct VerifyResponse
	err = json.NewDecoder(req.Body).Decode(&responseStruct)
	if err != nil {
		return false, fmt.Errorf("couldn't decode response from mCaptcha: %w", err)
	}

	return responseStruct.Valid, nil
}
