package accessToken

import (
	"fmt"
	// "github.com/kataras/iris/v12"
	"github.com/kataras/iris/v12/context"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Config struct {
	AccessCookieName string        `default:"accesstoken"`
	ExpiresDuration  time.Duration `default:"10"`
	RefreshDuration  time.Duration `default:"5"`
	Secret           string
	SecureCookie     bool `default:"false"`
}

type TokenStoreType uint

const (
	TOKENSTORE_COOKIE TokenStoreType = iota
	TOKENSTORE_HEADER
)

type TokenEvent func(context.Context, *Token) bool

type AccessToken struct {
	Config        *Config
	OnMustRefresh TokenEvent
	OnNoExists    TokenEvent
	OnSkip        TokenEvent
	TokenStore    TokenStoreType
}

type Token struct {
	jwt.StandardClaims
	RefreshAt int64
	Foo       map[string]interface{} `json:"foo"`
}

//创建token
func (a *AccessToken) SetToken(w http.ResponseWriter, CustomClaims map[string]interface{}) (string, error) {
	rsp := time.Now().Add(time.Minute * a.Config.ExpiresDuration) //必须刷新时间
	exp := rsp.Add(time.Minute * a.Config.RefreshDuration)        //完全失效时间
	claims := Token{
		jwt.StandardClaims{
			ExpiresAt: exp.Unix(),
			Issuer:    "test",
		},
		rsp.Unix(),
		CustomClaims,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(a.Config.Secret))
	err := a.writeToken(w, tokenString, exp)
	return tokenString, err
}

//解析token
func (a *AccessToken) ParseToken(tokenString string) (*Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Token{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(a.Config.Secret), nil
	})
	// if err != nil {
	// 	return nil, err
	// }
	if token != nil {
		if claims, ok := token.Claims.(*Token); ok {
			if token.Valid {
				return claims, nil
			}
			return claims, fmt.Errorf("token is incorrect")
		}
	}
	if err == nil {
		err = fmt.Errorf("token is incorrect")
	}
	return nil, err
}

//是否需要刷新
func (a *AccessToken) MustRefresh(tk *Token) bool {
	fmt.Println("RefreshAt:", tk.RefreshAt)
	fmt.Println("now:", time.Now().Unix())
	if tk.RefreshAt <= time.Now().Unix() {
		return true
	}
	return false
}

//判断登录中间件
func (a *AccessToken) MustLogin() context.Handler {
	return func(ctx context.Context) {
		if tkString, err := a.getToken(ctx.Request()); err == nil {
			tk, err := a.ParseToken(tkString)

			if err == nil {
				fmt.Println("3333:")
				if a.MustRefresh(tk) {
					if a.OnMustRefresh != nil {
						//必须刷新token
						a.OnMustRefresh(ctx, tk)
					}
					ctx.StopExecution()
				} else {
					ctx.Values().Set("token", tk.Foo)
					ctx.Next()
				}
				return
			}
			if tk != nil && a.OnSkip != nil && a.OnSkip(ctx, tk) {
				//app 跳过
				ctx.Values().Set("token", tk.Foo)
				ctx.Next()
				return
			}

			//token错误或者失效
			if a.OnNoExists != nil {
				a.OnNoExists(ctx, tk)
			}
			ctx.StopExecution()
			return
		}
		//token不存在
		if a.OnNoExists != nil {
			a.OnNoExists(ctx, nil)
		}
		ctx.StopExecution()
	}
}

//取token
func (a *AccessToken) getToken(req *http.Request) (string, error) {
	if tkString := req.URL.Query().Get("tk"); len(tkString) > 0 {
		return tkString, nil
	}
	switch a.TokenStore {
	case TOKENSTORE_COOKIE:
		cookie, err := req.Cookie(a.Config.AccessCookieName)
		if err != nil {
			return "", err
		}

		return cookie.Value, nil

	case TOKENSTORE_HEADER:
		bearer := req.Header.Get("Authorization")
		return strings.TrimPrefix(bearer, "Bearer "), nil

	default:
		return "", fmt.Errorf("%s", "unrecognized token store")
	}
}

//写token
func (a *AccessToken) writeToken(w http.ResponseWriter, token string, exp time.Time) error {
	switch a.TokenStore {
	case TOKENSTORE_HEADER:
		w.Header().Add("Authorization", "Bearer "+token)

	case TOKENSTORE_COOKIE:
		http.SetCookie(w, &http.Cookie{
			Name:     a.Config.AccessCookieName,
			Value:    token,
			Expires:  exp,
			Path:     "/",
			HttpOnly: true,
			Secure:   a.Config.SecureCookie,
		})

	default:
		return fmt.Errorf("%s", "unrecognized token store")
	}
	return nil
}

//删除token
func (a *AccessToken) RemoveToken(w http.ResponseWriter) error {
	http.SetCookie(w, &http.Cookie{
		Name:     a.Config.AccessCookieName,
		Value:    "",
		Expires:  time.Now(),
		Path:     "/",
		HttpOnly: true,
		Secure:   a.Config.SecureCookie,
	})

	return nil
}

//刷新token
func (a *AccessToken) RefreshToken(w http.ResponseWriter, CustomClaims map[string]interface{}) (string, error) {
	return a.SetToken(w, CustomClaims)
}
