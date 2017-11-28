package ssh

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

var ErrTimeout = errors.New("Cmd timedout")

type SSHConfig struct {
	Usr        string
	Passwd     string
	Passphrase string
	Host       string
}

func (c *SSHConfig) Connect() (*ssh.Client, error) {
	if c.Host == "" {
		return nil, errors.Wrap(nil, fmt.Sprintf("host is empty"))
	}

	//ssh.KeyboardInteractive()
	fnKeyboardInteractive := func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		// Just send the password back for all questions
		// fmt.Printf("user %s instruction %s q %v echos %v\n", user, instruction, questions, echos)
		answers := make([]string, len(questions))
		for i, _ := range answers {
			answers[i] = c.Passwd // replace this
		}

		return answers, nil
	}

	var auth []ssh.AuthMethod = make([]ssh.AuthMethod, 0)
	auth = append(auth, ssh.Password(c.Passwd))
	auth = append(auth, ssh.KeyboardInteractive(fnKeyboardInteractive))

	key, err := c.getKeyFile()
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, errors.Wrap(err, fmt.Sprintf("getKey"))
		}
	}

	// if id_rsa exists, add it.  Otherwise, move on
	if err == nil {
		auth = append(auth, ssh.PublicKeys(key))
	}

	cfg := &ssh.ClientConfig{
		User: c.Usr,
		Auth: []ssh.AuthMethod{
			ssh.Password(c.Passwd),
			ssh.KeyboardInteractive(fnKeyboardInteractive),
			// ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", c.Host+":22", cfg)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("Dial %s", c.Host))
	}
	return client, nil
}

func (c *SSHConfig) Run(client *ssh.Client, cmd string, strTime string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("NewSession"))
	}
	defer session.Close()

	t, err := time.ParseDuration(strTime)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("ParseDuration %s", strTime))
	}

	timeout := time.After(t)
	errc := make(chan error)

	var b bytes.Buffer
	session.Stdout = &b
	session.Stderr = &b

	go func() {
		select {
		case errc <- session.Run(cmd):
			close(errc)
		}
	}()

	select {

	case <-timeout:
		// if timeout, return w/ nil so we can move on to the next cmd (or stop?)
		return "", ErrTimeout
	case err := <-errc:
		if err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("cmd err: %s", cmd))
		}
	}

	return b.String(), nil
}

func (c *SSHConfig) getKeyFile() (ssh.Signer, error) {
	var key ssh.Signer
	var err error

	usr, _ := user.Current()
	f := usr.HomeDir + "~/.ssh/id_rsa"
	buf, err := ioutil.ReadFile(f)
	if os.IsNotExist(err) {
		return key, err
	}

	if err != nil {
		return key, errors.Wrap(err, fmt.Sprintf("ReadFile %s", f))
	}

	if c.Passphrase == "" {
		return key, nil
	}

	if c.Passphrase == "NOPHRASE" {
		key, err = ssh.ParsePrivateKey(buf)
		if err != nil {
			return key, errors.Wrap(err, fmt.Sprintf("ParsePrivateKey"))
		}
		return key, nil
	}

	key, err = ssh.ParsePrivateKeyWithPassphrase(buf, []byte(c.Passphrase))
	if err != nil {
		return key, errors.Wrap(err, fmt.Sprintf("ParsePrivateKeyWithPassphrase"))
	}

	return key, nil
}
