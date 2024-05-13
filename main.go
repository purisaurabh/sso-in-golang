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
	provider, err := oidc.NewProvider(context.Background(), os.Getenv("AUTH_DOMAIN"))
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
	// adding the middleware to the router r
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, _ := store.Get(r, "state")
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

func ProfileHandler(w http.ResponseWriter, r *http.Request) {

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

	fmt.Println("User Information in profile handler : ", userInfo)

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

	tmpl.ExecuteTemplate(w, "profile.html", map[string]interface{}{"profile": profile})
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

	session.Values["state"] = state

	err = sessions.Save(r, w)
	if err != nil {
		fmt.Println("Error saving session: ", err)
		http.Error(w, "could not save session: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline), http.StatusTemporaryRedirect)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("You are logged in")

	session, ok := r.Context().Value("session").(*sessions.Session)
	if !ok {
		http.Error(w, "could not get session", http.StatusInternalServerError)
		return
	}

	sessionState, ok := session.Values["state"].(string)
	if !ok {
		http.Error(w, "could not get state from session", http.StatusInternalServerError)
		return
	}

	urlState := r.URL.Query().Get("state")
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

	id_token, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "could not get id token", http.StatusInternalServerError)
		return
	}

	fmt.Println("ID Token: ", id_token)

	if !token.Valid() {
		http.Error(w, "invalid access token", http.StatusInternalServerError)
		return
	}

	client := oauthConfig.Client(r.Context(), token)

	resp, err := client.Get(os.Getenv("USER_INFO"))
	if err != nil {
		http.Error(w, "could not fetch user information", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "could not parse response body", http.StatusInternalServerError)
		return
	}

	fmt.Println("User Info: ", string(b))
	fmt.Println("Access Token: ", token.AccessToken)
	fmt.Println("Access Token: ", token.RefreshToken)

	userInfo := url.QueryEscape(string(b))

	userCookie := &http.Cookie{
		Name:     "u",
		Value:    userInfo,
		Expires:  time.Now().Add(1 * time.Hour),
		Path:     "/",
		Domain:   "localhost",
		HttpOnly: true,
		Secure:   true,
	}

	http.SetCookie(w, userCookie)

	tokenCookie := &http.Cookie{
		Name:     "at",
		Value:    token.AccessToken,
		Expires:  time.Now().Add(1 * time.Hour),
		Path:     "/",
		Domain:   "localhost",
		HttpOnly: true,
		Secure:   true,
	}

	http.SetCookie(w, tokenCookie)

	http.Redirect(w, r, "/profile", http.StatusTemporaryRedirect)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {

	accessTokenCookie, err := r.Cookie("at")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	accessToken := accessTokenCookie.Value

	// Delete all the cookies and session values
	http.SetCookie(w, &http.Cookie{Name: "at", Value: "", MaxAge: -1, Path: "/", Secure: false, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "u", Value: "", MaxAge: -1, Path: "/", Secure: false, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "state", Value: "", MaxAge: -1, Path: "/", Secure: false, HttpOnly: true})

	_, err = http.PostForm("https://oauth2.googleapis.com/revoke", url.Values{"token": {accessToken}})
	if err != nil {
		http.Error(w, "could not logout", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// before redicted to profile router we have to check whether the user is authenticated or not

func isAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the access token cookie
		accessTokenCookie, err := r.Cookie("at")
		if err != nil || accessTokenCookie.Value == "" {
			// Cookie does not exist or is empty, hence redirect user to home page
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
