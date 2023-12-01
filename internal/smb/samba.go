package smb

import (
	"errors"
	"fmt"
	"github.com/hirochachacha/go-smb2"
	log "github.com/sirupsen/logrus"
	"net"
	netURL "net/url"
	"os"
	"os/user"
	"strings"
)

type ServiceInterface interface {
	FetchFileContents(url string) ([]byte, error)
}

type Properties struct {
	Url       string
	Host      string
	Port      string
	User      string
	Password  string
	Domain    string
	ShareName string
	FilePath  string
}

type Service struct{}

func NewSambaService() ServiceInterface {
	return &Service{}
}

func (s *Service) FetchFileContents(url string) ([]byte, error) {
	var contents []byte
	p, err := ParseUrl(url)
	if err != nil {
		return contents, err
	}

	pwdOutput := "***"
	if p.Password == "" {
		pwdOutput = "none"
	}
	// by usage, this method is called before log level is set
	// so Debugf statement here is not effective
	log.Infof("fetching remote file server: %s:%s, user: %s, pwd: %s, domain: %s, share: %s, path: %s",
		p.Host, p.Port, p.User, pwdOutput, p.Domain, p.ShareName, p.FilePath)

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", p.Host, p.Port))
	if err != nil {
		return contents, err
	}
	defer func(conn net.Conn) {
		err = conn.Close()
	}(conn)

	dialer := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     p.User,
			Password: p.Password,
			Domain:   p.Domain,
		},
	}

	session, err := dialer.Dial(conn)
	if err != nil {
		return contents, err
	}
	defer func(session *smb2.Session) {
		err = session.Logoff()
	}(session)

	fs, err := session.Mount(p.ShareName)
	if err != nil {
		return contents, err
	}
	defer func(fs *smb2.Share) {
		err = fs.Umount()
	}(fs)

	contents, err = fs.ReadFile(p.FilePath)
	return contents, err
}

// ParseUrl - parses according to https://www.iana.org/assignments/uri-schemes/prov/smb
// except for the query string
// smb://[[<domain>;]<username>[:<password>]@]<server>[:<port>][/[<share>[/[<path>]]][?[<param>=<value>[;<param2>=<value2>[...]]]]]
func ParseUrl(url string) (Properties, error) {
	p := Properties{}
	p.Url = url
	u, err := netURL.Parse(url)
	if err != nil {
		return p, err
	}

	if u.Scheme != "smb" {
		return p, errors.New("invalid scheme")
	}
	p.Host = u.Hostname()
	if p.Host == "" {
		return p, errors.New("missing hostname")
	}
	p.Port = u.Port()
	if p.Port == "" {
		p.Port = "445"
	}

	splits := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(splits) < 2 {
		return p, errors.New("invalid path spec, expecting shareName and filePath to be included: " + u.Path)
	}

	p.ShareName = splits[0]
	p.FilePath = strings.Join(splits[1:], "/")

	// smb url spec allows for domain in front of user with a semicolon
	splits = strings.Split(u.User.Username(), ";")
	if len(splits) == 1 {
		p.User = splits[0]
	} else if len(splits) == 2 {
		p.Domain = splits[0]
		p.User = splits[1]
	}

	if p.User == "" {
		curUser, err := user.Current()
		if err != nil {
			return p, err
		}
		p.User = curUser.Username
	}
	if p.User == "root" {
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			p.User = sudoUser
		}
	}

	p.Password, _ = u.User.Password()
	if p.Password == "*" {
		fmt.Println("Please enter smb password: ")
		_, err := fmt.Scanln(&p.Password)
		if err != nil {
			return p, err
		}
	}

	return p, nil
}
