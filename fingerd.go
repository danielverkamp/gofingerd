/*
  gofingerd: simple finger (RFC 1288) daemon in Go
  Copyright (C) 2012 Daniel Verkamp <daniel@drv.nu>

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.
*/

package main

import (
	"bufio"
	"flag"
	"net"
	"net/textproto"
	"os"
	"os/user"
	"fmt"
	"time"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"io/ioutil"
)

var listen_port *int = flag.Int("p", 79, "listen port")
var listen_intf *string = flag.String("i", "", "listen on interface")

func log(msg string) {
	fmt.Fprintf(os.Stdout, "%s: %s\n", time.LocalTime().String(), msg)
}

var my_hostname string

func main() {
	flag.Parse()

	service := fmt.Sprintf("%s:%v", *listen_intf, *listen_port)

	log("gofingerd starting...")
	log("attempting to listen on " + service + "...")

	tcpAddr, err := net.ResolveTCPAddr("ip4", service)
	checkError(err)

	listener, err := net.ListenTCP("tcp", tcpAddr)
	checkError(err)

	hostnames, err := net.LookupAddr(*listen_intf)
	if err == nil {
		my_hostname = hostnames[0]
	}

	if my_hostname == "" {
		my_hostname = *listen_intf
	}

	if my_hostname == "" {
		my_hostname, _ = os.Hostname()
	}

	log("listening on " + my_hostname + ":" + strconv.Itoa(*listen_port))

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	bio := bufio.NewReader(conn)
	tp := textproto.NewReader(bio)
	query, err := tp.ReadLine()
	if err != nil {
		log("Error reading line: " + err.String())
		return
	}

	log("query from " + conn.RemoteAddr().String() + ": " + strconv.Quote(query))

	conn.Write([]byte(handleQuery(query)))
	conn.Close()
}

var list_users_re = regexp.MustCompile("^[ ]*(/[wW])?[ ]*$")
var forward_re = regexp.MustCompile("@") // don't bother matching anything, just deny forward requests
var user_re = regexp.MustCompile("^[ ]*((/[wW])[ ]+)?([a-zA-Z0-9!()_\\-.?\\[\\]`~]+)[ ]*$")

func handleQuery(query string) string {
	if forward_matches := forward_re.FindStringSubmatch(query); forward_matches != nil {
		return handleForwardQuery(query)
	}

	if list_users_matches := list_users_re.FindStringSubmatch(query); list_users_matches != nil {
		verbose := strings.ToUpper(list_users_matches[1]) == "/W"
		return handleListUsersQuery(verbose)
	}

	if user_matches := user_re.FindStringSubmatch(query); user_matches != nil {
		user := user_matches[3]
		verbose := strings.ToUpper(user_matches[1]) == "/W"
		return handleUserQuery(user, verbose)
	}

	return "\r\n"
}

func handleForwardQuery(query string) string {
	return "Finger forwarding service denied\r\n"
}

func handleListUsersQuery(verbose bool) string {
	return "Welcome to " + my_hostname + "!\r\n" + "Uptime: " + uptime() + "\r\n"
}

func handleUserQuery(user string, verbose bool) string {
	var response string

	exists, name, plan := userinfo(user)

	if exists {
		response = "User: " + user + "\r\n"
		response += "Name: " + name + "\r\n"
		response += "Plan: " + plan + "\r\n"
	} else {
		response = user + ": no such user\r\n"
	}

	return response
}

func uptime() string {
	var sysinfo syscall.Sysinfo_t
	errno := syscall.Sysinfo(&sysinfo)
	if errno == 0 {
		seconds := sysinfo.Uptime

		minutes := seconds / 60
		seconds -= minutes * 60

		hours := minutes / 60
		minutes -= hours * 60

		days := hours / 24
		hours -= days * 24

		return fmt.Sprintf("%v days %v:%02v:%02v", days, hours, minutes, seconds)
	}

	return "unknown"
}

func userinfo(username string) (exists bool, name, plan string) {

	u, err := user.Lookup(username)

	if err == nil {
		var plan string
		planbytes, err := ioutil.ReadFile(u.HomeDir + "/.plan")
		if err != nil {
			plan = "no plan"
		} else {
			plan = string(planbytes)
		}
		return true, u.Name, plan
	}

	return false, "", ""
}

func checkError(err os.Error) {
	if err != nil {
		log("fatal error: " + err.String())
		os.Exit(1)
	}
}
