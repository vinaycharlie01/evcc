package idkproxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/evcc-io/evcc/util"
	"github.com/evcc-io/evcc/util/request"
	"github.com/evcc-io/evcc/util/urlvalues"
	"github.com/evcc-io/evcc/vehicle/vag"
	"github.com/evcc-io/evcc/vehicle/vag/cariad"
)

// https://emea.bff.cariad.digital/login/v1/idk/openid-configuration
const WellKnown = cariad.BaseURL + "/login/v1/idk/openid-configuration"

var Config = &oidc.ProviderConfig{
	AuthURL:  "https://identity.vwgroup.io/oidc/v1/authorize",
	TokenURL: cariad.BaseURL + "/login/v1/idk/token",
}

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

// https://github.com/arjenvrh/audi_connect_ha/issues/133

var qmSecret = []byte{26, 256 - 74, 256 - 103, 37, 256 - 84, 23, 256 - 102, 256 - 86, 78, 256 - 125, 256 - 85, 256 - 26, 113, 256 - 87, 71, 109, 23, 100, 24, 256 - 72, 91, 256 - 41, 6, 256 - 15, 67, 108, 256 - 95, 91, 256 - 26, 71, 256 - 104, 256 - 100}

const qmClientId = "01da27b0"

func qmauth(ts int64) string {
	hash := hmac.New(sha256.New, qmSecret)
	hash.Write([]byte(strconv.FormatInt(ts, 10)))
	return hex.EncodeToString(hash.Sum(nil))
}

func qmauthNow() string {
	return "v1:" + qmClientId + ":" + qmauth(time.Now().Unix()/100)
}

// Exchange exchanges an VAG identity token for an IDK token
func (v *Service) Exchange(q url.Values) (*vag.Token, error) {
	if err := urlvalues.Require(q, "code", "code_verifier"); err != nil {
		return nil, err
	}

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"response_type": {"token id_token"},
		"code":          {q.Get("code")},
		"code_verifier": {q.Get("code_verifier")},
	}

	urlvalues.Merge(data, v.data)

	var res vag.Token

	req, err := request.New(http.MethodPost, Config.TokenURL, strings.NewReader(data.Encode()), map[string]string{
		"Content-Type": request.FormContent,
		"Accept":       request.JSONContent,
		"x-qmauth":     qmauthNow(),
	})
	if err == nil {
		err = v.DoJSON(req, &res)
	}

	return &res, err
}

// Refresh refreshes an IDK token
func (v *Service) Refresh(token *vag.Token) (*vag.Token, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"response_type": {"token id_token"},
		"refresh_token": {token.RefreshToken},
	}

	urlvalues.Merge(data, v.data)

	var res vag.Token

	req, err := request.New(http.MethodPost, Config.TokenURL, strings.NewReader(data.Encode()), map[string]string{
		"Content-Type": request.FormContent,
		"Accept":       request.JSONContent,
		"x-qmauth":     qmauthNow(),
	})
	if err == nil {
		err = v.DoJSON(req, &res)
	}

	return &res, err
}

// TokenSource creates token source. Token is refreshed automatically.
func (v *Service) TokenSource(token *vag.Token) vag.TokenSource {
	return vag.RefreshTokenSource(token, v.Refresh)
}
