package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	// Logging
	"github.com/unrolled/logger"

	// Stats/Metrics
	"github.com/rcrowley/go-metrics"
	"github.com/rcrowley/go-metrics/exp"
	"github.com/thoas/stats"

	"github.com/GeertJohan/go.rice"
	"github.com/NYTimes/gziphandler"
	"github.com/julienschmidt/httprouter"

	// auth/sessions
	"github.com/gorilla/sessions"
)

// Counters ...
type Counters struct {
	r metrics.Registry
}

func NewCounters() *Counters {
	counters := &Counters{
		r: metrics.NewRegistry(),
	}
	return counters
}

func (c *Counters) Inc(name string) {
	metrics.GetOrRegisterCounter(name, c.r).Inc(1)
}

func (c *Counters) Dec(name string) {
	metrics.GetOrRegisterCounter(name, c.r).Dec(1)
}

func (c *Counters) IncBy(name string, n int64) {
	metrics.GetOrRegisterCounter(name, c.r).Inc(n)
}

func (c *Counters) DecBy(name string, n int64) {
	metrics.GetOrRegisterCounter(name, c.r).Dec(n)
}

// Server ...
type Server struct {
	bind      string
	config    Config
	templates *Templates
	router    *httprouter.Router

	// Logger
	logger *logger.Logger

	// Stats/Metrics
	counters *Counters
	stats    *stats.Stats
}

func (s *Server) render(name string, w http.ResponseWriter, ctx interface{}) {
	buf, err := s.templates.Exec(name, ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if buf != nil {
		_, err = buf.WriteTo(w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

/* LOGIN STUFF */

//Store the cookie store which is going to store session data in the cookie
var Store = sessions.NewCookieStore([]byte("secret-password"))

//IsLoggedIn will check if the user has an active session and return True
func IsLoggedIn(r *http.Request) bool {
    session, _ := Store.Get(r, "session")
    if session.Values["loggedin"] == "true" {
        return true
    }
    return false
}

func (s *Server) LoginHandler() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		s.counters.Inc("n_login")
		// var uname = r.FormValue("Username")
		// var pass = r.FormValue("Password")

		// copypasta
		session, err := sessions.Store.Get(Store, r, "session")

		if err != nil {
			s.render("login", w, nil)
			// in case of error during 
			// fetching session info, execute login template
			} else {
			isLoggedIn := session.Values["loggedin"]
			if isLoggedIn != "true" {
				if r.Method == "POST" {
					if r.FormValue("pass") == "***REMOVED***" && r.FormValue("uname") == "***REMOVED***" {
						session.Values["loggedin"] = "true"
						session.Save(r, w)
						http.Redirect(w, r, "/", http.StatusFound)
						return
					}else{
						http.Redirect(w, r, "/login", http.StatusFound)
					}
				} else if r.Method == "GET" {
					s.render("login", w, nil)
				}
			} else {
				http.Redirect(w, r, "/", http.StatusFound)
			}
		}
	}
}

func (s *Server) LogoutHandler() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		session, err := sessions.Store.Get(Store, r, "session")
    	if err == nil { //If there is no error, then remove session
			if session.Values["loggedin"] != "false" {
				session.Values["loggedin"] = "false"
				session.Save(r, w)
			}
    	}
    	http.Redirect(w, r, "/", 302) 
	}
}
// IndexHandler ...
func (s *Server) IndexHandler() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		var (
			q    string
			cmd  string
			args []string
		)

		s.counters.Inc("n_index")
		var test = strings.Split(r.URL.Path, "/");
		if len(test) < 3{
			q = "";
		}else{
			q=test[2];
		}
		// Query ?q=
		// q = r.URL.Query().Get("q")
		// q = 

		// Form name=q
		if q == "" {
			q = r.FormValue("q")
		}

		if q != "" {
			tokens := strings.Split(q, " ")
			if len(tokens) > 0 {
				cmd, args = tokens[0], tokens[1:]
			}
		} else {
			cmd = p.ByName("command")
			args = strings.Split(p.ByName("args"), "/")
		}

		if cmd == "" {
			s.render("index", w, nil)
		} else {
			if command := LookupCommand(cmd); command != nil {
				if IsLoggedIn(r) {
					err := command.Exec(w, r, args)
					if err != nil {
						http.Error(
							w,
							fmt.Sprintf(
								"Error processing command %s: %s",
								command.Name(), err,
							),
							http.StatusInternalServerError,
						)
					}
				} else {
					http.Redirect(w, r, "/login", 302)
				}
			} else if bookmark, ok := LookupBookmark(cmd); ok {
				q := strings.Join(args, " ")
				bookmark.Exec(w, r, q)
			} else {
				if s.config.URL != "" {
					url := s.config.URL
					if q != "" {
						url = fmt.Sprintf(url, q)
					}
					http.Redirect(w, r, url, http.StatusFound)
				} else {
					http.Error(
						w,
						fmt.Sprintf("Invalid Command: %v", cmd),
						http.StatusBadRequest,
					)
				}
			}
		}
	}
}

// HelpHandler ...
func (s *Server) HelpHandler() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		s.counters.Inc("n_help")

		s.render("help", w, nil)
	}
}

// OpenSearchHandler ...
func (s *Server) OpenSearchHandler() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		s.counters.Inc("n_opensearch")

		w.Header().Set("Content-Type", "text/xml")
		w.Write(
			[]byte(fmt.Sprintf(
				OpenSearchTemplate,
				s.config.Title,
				s.config.FQDN,
			)),
		)
	}
}

func (s *Server) StaticHandler() httprouter.Handle{
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		var q = r.URL.Path
		w.Header().Set("Content-Type", "text/css")

		w.Write([]byte(rice.MustFindBox("templates").MustString(q)))
	}
}

// StatsHandler ...
func (s *Server) StatsHandler() httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		
		bs, err := json.Marshal(s.stats.Data())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		w.Write(bs)
	}
}

// ListenAndServe ...
func (s *Server) ListenAndServe() {
	log.Fatal(
		http.ListenAndServe(
			s.bind,
			s.logger.Handler(
				s.stats.Handler(
					gziphandler.GzipHandler(
						s.router,
					),
				),
			),
		),
	)
}


func (s *Server) initRoutes() {
	s.router.Handler("GET", "/debug/metrics", exp.ExpHandler(s.counters.r))
	// s.router.GET("/static/style.css", s.StaticHandler())
	s.router.ServeFiles("/static/*filepath", /*http.Dir("templates")*/ rice.MustFindBox("templates").HTTPBox())
	s.router.GET("/debug/stats", s.StatsHandler())

	s.router.GET("/", s.IndexHandler())
	s.router.GET("/q/:link", s.IndexHandler())
	s.router.POST("/", s.IndexHandler())
	s.router.GET("/login", s.LoginHandler())
	s.router.POST("/login", s.LoginHandler())
	s.router.GET("/logout", s.LogoutHandler())
	s.router.GET("/help", s.HelpHandler())
	s.router.GET("/opensearch.xml", s.OpenSearchHandler())
}

// NewServer ...
func NewServer(bind string, config Config) *Server {
	server := &Server{
		bind:      bind,
		config:    config,
		router:    httprouter.New(),
		templates: NewTemplates("base"),

		// Logger
		logger: logger.New(logger.Options{
			Prefix:               "golinks",
			RemoteAddressHeaders: []string{"X-Forwarded-For"},
			OutputFlags:          log.LstdFlags,
		}),

		// Stats/Metrics
		counters: NewCounters(),
		stats:    stats.New(),
	}
	
	// Templates
	box := rice.MustFindBox("templates")

	indexTemplate := template.New("index")
	template.Must(indexTemplate.Parse(box.MustString("index.html")))
	template.Must(indexTemplate.Parse(box.MustString("base.html")))

	helpTemplate := template.New("help")
	template.Must(helpTemplate.Parse(box.MustString("help.html")))
	template.Must(helpTemplate.Parse(box.MustString("base.html")))

	loginTemplate := template.New("login")
	template.Must(loginTemplate.Parse(box.MustString("login.html")))
	template.Must(loginTemplate.Parse(box.MustString("base.html")))

	server.templates.Add("index", indexTemplate)
	server.templates.Add("help", helpTemplate)
	server.templates.Add("login", loginTemplate)

	server.initRoutes()

	return server
}
