package tokenrefreshservice

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/evcc-io/evcc/util"
	"github.com/evcc-io/evcc/util/request"
	"github.com/evcc-io/evcc/util/urlvalues"
	"github.com/evcc-io/evcc/vehicle/skoda"
	"github.com/evcc-io/evcc/vehicle/vag"
)

const (
	BaseURL         = "https://tokenrefreshservice.apps.emea.vwapps.io"
	CodeExchangeURL = BaseURL + "/exchangeAuthCode"
	RefreshTokenURL = BaseURL + "/refreshTokens"
)

var _ vag.TokenExchanger = (*Service)(nil)

type Service struct {
	*request.Helper
	data url.Values
}

func New(log *util.Logger, q url.Values) *Service {
	return &Service{
		Helper: request.NewHelper(log),
		data:   q,
	}
}

func (v *Service) Exchange(q url.Values) (*vag.Token, error) {
	if err := urlvalues.Require(q, "id_token", "code"); err != nil {
		return nil, err
	}

	data := map[string]string{
		"authorizationCode": q.Get("code"),
	}

	var res vag.Token

	uri := fmt.Sprintf("%s/v1/authentication/token?systemId=%s", skoda.BaseURI, "TECHNICAL")
	req, err := request.New(http.MethodPost, uri, request.MarshalJSON(data), map[string]string{
		"Content-type":    request.JSONContent,
		"Authorization":   "Bearer " + q.Get("id_token"),
		"user-agent":      "OneConnect/000000117 CFNetwork/1240.0.4 Darwin/20.6.0",
		"accept-language": "de-de",
		"accept":          "*/*",
	})
	if err == nil {
		err = v.DoJSON(req, &res)
	}

	os.Exit(1)

	return &res, err
}

func (v *Service) Refresh(token *vag.Token) (*vag.Token, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token.RefreshToken},
	}

	urlvalues.Merge(data, v.data)

	var res vag.Token

	req, err := request.New(http.MethodPost, RefreshTokenURL, strings.NewReader(data.Encode()), request.URLEncoding)
	if err == nil {
		err = v.DoJSON(req, &res)
	}

	return &res, err
}

// TokenSource creates token source. Token is refreshed automatically.
func (v *Service) TokenSource(token *vag.Token) vag.TokenSource {
	return vag.RefreshTokenSource(token, v.Refresh)
}
