package zmodules

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type HTTPFlags struct {
	zgrab2.BaseFlags
	HTTP HTTPOptions `json:"http"`
}

type HTTPOptions struct {
	Method       string `long:"method" default:"GET" description:"Set HTTP request method type"`
	Endpoint     string `long:"endpoint" default:"/" description:"Send an HTTP request to an endpoint"`
	UserAgent    string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`
	ProxyDomain  string `long:"proxy-domain" description:"Send a CONNECT <domain> first"`
	MaxSize      int    `long:"max-size" default:"256" description:"Max kilobytes to read in response to an HTTP request"`
	MaxRedirects int    `long:"max-redirects" default:"0" description:"Max number of redirects to follow"`
}

type HTTPRequest struct {
	Method    string `json:"method,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Body      string `json:"body,omitempty"`
}

type HTTPResponse struct {
	VersionMajor int    `json:"version_major,omitempty"`
	VersionMinor int    `json:"version_minor,omitempty"`
	StatusCode   int    `json:"status_code,omitempty"`
	StatusLine   string `json:"status_line,omitempty"`
	//Headers      HTTPHeaders `json:"headers,omitempty"`
	Body       string `json:"body,omitempty"`
	BodySHA256 []byte `json:"body_sha256,omitempty"`
}

type HTTPResults struct {
	ProxyRequest  *HTTPRequest  `json:"connect_request,omitempty"`
	ProxyResponse *HTTPResponse `json:"connect_response,omitempty"`
	//Response              *http.Response   `json:"response,omitempty"`
	//RedirectResponseChain []*http.Response `json:"redirect_response_chain,omitempty"`
}

type HTTPModule struct {
}

type HTTPScanner struct {
}

func init() {
	var httpModule HTTPModule
	_, err := zgrab2.AddCommand("http", "HTTP Banner Grab", "Grab a banner over HTTP", 80, &httpModule)
	if err != nil {
		log.Fatal(err)
	}
}

func (m *HTTPModule) NewFlags() ScanFlags {
	return new(HTTPFlags)
}

func (m *HTTPModule) NewScanner() Scanner {
	return new(HTTPScanner)
}

func (f *HTTPFlags) Validate(args []string) error {
	return nil
}

func (f *HTTPFlags) Help() string {
	return ""
}

func (s *HTTPScanner) Init(name string, flags zgrab2.ScanFlags) error {
	//httpFlags := flags.(*HTTPFlags)

	zgrab2.RegisterScanner(name, s)
	return nil
}

func (s *HTTPScanner) InitPerSender(senderID int) error {
	return nil
}

func (s *HTTPScanner) GetName() string {
	return ""
}

func (s *HTTPScanner) Scan(t zgrab2.ScanTarget, port uint) (interface{}, error) {
	http := HTTPRequest{Method: "Get", Body: "testing"}
	ret := HTTPResults{ProxyRequest: &http}
	return ret, nil
}