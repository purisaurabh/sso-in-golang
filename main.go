package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

type UserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Locale        string `json:"locale"`
	Hd            string `json:"hd"`
}

func NewOauth2Config() (*oauth2.Config, error) {
	provider, err := oidc.NewProvider(context.Background(), "https://accounts.google.com")
	if err != nil {
		return nil, fmt.Errorf("could not create new provider: %v", err)
	}

	oauthConfig := &oauth2.Config{
		RedirectURL:  os.Getenv("REDIRECT_URI"),
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		Endpoint:     provider.Endpoint(),
	}

	return oauthConfig, nil
}

var oauthConfig *oauth2.Config
var store *sessions.CookieStore

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	store = sessions.NewCookieStore([]byte(os.Getenv("SECRETE_KEY")))

	oauthConfig, err = NewOauth2Config()
	if err != nil {
		log.Fatal("Error creating OAuth2 configuration: ", err)
	}

	r := mux.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, _ := store.Get(r, "auth-sessions")
			ctx := context.WithValue(r.Context(), "session", session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	r.PathPrefix("/public/").Handler(http.StripPrefix("/public/", http.FileServer(http.Dir("web/static"))))
	fmt.Println("Starting the application...")
	r.HandleFunc("/login", loginHandler)
	r.HandleFunc("/callback", callbackHandler)
	r.HandleFunc("/logout", logoutHandler)

	r.HandleFunc("/", PingHandler)
	r.Handle("/profile", isAuthenticated(http.HandlerFunc(ProfileHandler)))
	http.ListenAndServe(":4000", r)
}

func PingHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseGlob("web/template/*")
	tmpl.ExecuteTemplate(w, "home.html", nil)
}

// func ProfileHandler(w http.ResponseWriter, r *http.Request) {
// 	tmpl, err := template.ParseGlob("web/template/*")
// 	if err != nil {

// 		fmt.Println("Error parsing template: ", err)
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	tmpl.ExecuteTemplate(w, "profile.html", nil)
// }

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	// Get the user information from the cookie
	cookie, err := r.Cookie("u")
	if err != nil {
		http.Error(w, "Could not get user cookie", http.StatusInternalServerError)
		return
	}

	// URL decode the user information
	fmt.Println("Cookie Value: ", cookie.Value)
	userInfo, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		http.Error(w, "Could not decode user information", http.StatusInternalServerError)
		return
	}

	fmt.Println("User Information : ", userInfo)

	// Parse the user information into a Profile object
	var profile UserInfo
	err = json.Unmarshal([]byte(userInfo), &profile)
	if err != nil {
		http.Error(w, "Could not parse user information", http.StatusInternalServerError)
		return
	}

	tmpl, err := template.ParseGlob("web/template/*")
	if err != nil {
		fmt.Println("Error parsing template: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Pass the profile data to the template
	tmpl.ExecuteTemplate(w, "profile.html", profile)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := generateRandomString()
	if err != nil {
		fmt.Println("Error generating random string: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Println("Login Page")
	fmt.Println("State: ", state)

	session, ok := r.Context().Value("session").(*sessions.Session)
	if !ok {
		http.Error(w, "could not get session", http.StatusInternalServerError)
		return
	}

	// Save state value in session
	session.Values["state"] = state

	err = sessions.Save(r, w)
	if err != nil {
		fmt.Println("Error saving session: ", err)
		http.Error(w, "could not save session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline), http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("You are logged in")

	// TODO : to validate the state
	session, ok := r.Context().Value("session").(*sessions.Session)
	if !ok {
		http.Error(w, "could not get session", http.StatusInternalServerError)
		return
	}

	// Get state value from session
	sessionState, ok := session.Values["state"].(string)
	if !ok {
		http.Error(w, "could not get state from session", http.StatusInternalServerError)
		return
	}

	// Get state parameter from URL
	urlState := r.URL.Query().Get("state")

	// Compare state values
	if sessionState != urlState {
		http.Error(w, "invalid state param", http.StatusInternalServerError)
		return
	}

	code := r.URL.Query().Get("code")
	token, err := oauthConfig.Exchange(r.Context(), code)
	if err != nil {

		http.Error(w, "could not exchange oauth code", http.StatusInternalServerError)
		return
	}

	if !token.Valid() {
		http.Error(w, "invalid access token", http.StatusInternalServerError)
		return
	}

	// get the user information
	// Create a new HTTP client using the OAuth2 token
	client := oauthConfig.Client(r.Context(), token)

	// Send a GET request to the Auth0 userinfo endpoint
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		http.Error(w, "could not fetch user information", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read and parse the response body
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "could not parse response body", http.StatusInternalServerError)
		return
	}

	fmt.Println("User Info: ", string(b))
	fmt.Println("Access Token: ", token.AccessToken)

	// TODO : cookie should be ecrypted
	// store the user information and the access token in the cookie
	// before storing in the  cookie it should be encrypted
	userInfo := url.QueryEscape(string(b))

	// fmt.Println("User Info: ", userInfo)

	userCookie := &http.Cookie{
		Name:     "u",
		Value:    userInfo,
		Expires:  time.Now().Add(1 * time.Hour),
		Path:     "/",
		Domain:   "localhost",
		HttpOnly: true,
		Secure:   true,
	}

	// Set the user information cookie
	http.SetCookie(w, userCookie)

	// Create a new cookie for the access token
	tokenCookie := &http.Cookie{
		Name:     "at",
		Value:    token.AccessToken,
		Expires:  time.Now().Add(1 * time.Hour),
		Path:     "/",
		Domain:   "localhost",
		HttpOnly: true,
		Secure:   true,
	}

	// Set the access token cookie
	http.SetCookie(w, tokenCookie)

	http.Redirect(w, r, "/profile", http.StatusTemporaryRedirect)
}

// logout handler
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Delete all the cookies and session values
	// Set cookie timestamp as negative
	http.SetCookie(w, &http.Cookie{Name: "at", Value: "", MaxAge: -1, Path: "/", Secure: false, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "u", Value: "", MaxAge: -1, Path: "/", Secure: false, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "auth-sessions", Value: "", MaxAge: -1, Path: "/", Secure: false, HttpOnly: true})

	// Call auth0 logout endpoint to clear session and tokens from auth0 side
	logoutURL, err := url.Parse("https://" + os.Getenv("AUTH0_DOMAIN") + "/v2/logout")
	if err != nil {
		http.Error(w, "could not logout", http.StatusInternalServerError)
		return
	}

	// Check if request was performed via http or https
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	// Redirecting user back to homepage
	redirectionURL, err := url.Parse(scheme + "://" + r.Host)
	if err != nil {
		http.Error(w, "could not parse URL", http.StatusInternalServerError)
		return
	}

	// Add url params
	parameters := url.Values{}
	parameters.Add("returnTo", redirectionURL.String())
	parameters.Add("client_id", os.Getenv("AUTH0_CLIENT_ID"))
	logoutURL.RawQuery = parameters.Encode()

	http.Redirect(w, r, logoutURL.String(), http.StatusTemporaryRedirect)
}

// func logoutHandler(w http.ResponseWriter, r *http.Request) {
//     // Retrieve the access token from the "at" cookie
//     accessTokenCookie, err := r.Cookie("at")
//     if err != nil {
//         http.Error(w, "Unauthorized", http.StatusUnauthorized)
//         return
//     }
//     accessToken := accessTokenCookie.Value

//     // Delete all the cookies and session values
//     // Set cookie timestamp as negative
//     http.SetCookie(w, &http.Cookie{Name: "at", Value: "", MaxAge: -1, Path: "/", Secure: false, HttpOnly: true})
//     http.SetCookie(w, &http.Cookie{Name: "u", Value: "", MaxAge: -1, Path: "/", Secure: false, HttpOnly: true})
//     http.SetCookie(w, &http.Cookie{Name: "auth-sessions", Value: "", MaxAge: -1, Path: "/", Secure: false, HttpOnly: true})

//     // Call Google's token revocation endpoint to clear session and tokens from Google's side
//     logoutURL, err := url.Parse("https://accounts.google.com/o/oauth2/revoke?token=" + accessToken)
//     if err != nil {
//         http.Error(w, "could not logout", http.StatusInternalServerError)
//         return
//     }

//     // Redirecting user back to homepage
//     http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
// }

// before redicted to profile router we have to check whether the user is authenticated or not

func isAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the access token cookie
		accessTokenCookie, err := r.Cookie("at")
		if err != nil || accessTokenCookie.Value == "" {
			// Cookie does not exist or is empty, hence redirect user to home page or login page
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		// If everything is okay, forward the request to the next handler
		next.ServeHTTP(w, r)
	})
}

func generateRandomString() (string, error) {
	str := make([]byte, 32)
	_, err := rand.Read(str)
	if err != nil {
		return "", err
	}

	state := base64.URLEncoding.EncodeToString(str)
	return state, nil
}
