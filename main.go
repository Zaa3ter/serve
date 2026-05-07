package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) != 3 {
		panic("serve [address]:<port> <app>")
	}
	l, err := net.Listen("tcp", os.Args[1])
	if err != nil {
		panic(err)
	}
	fmt.Println("listen on ", l.Addr().String())

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	hostKey, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		panic(err)
	}

	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	config.AddHostKey(hostKey)
	for {
		netCon, err := l.Accept()
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		sshCon, newChannals, GlobalReqs, err := ssh.NewServerConn(netCon, config)
		if err != nil {
			fmt.Println(err.Error())
			continue
		}

		clint := &sshClint{
			connection:  *sshCon,
			newChannels: newChannals,
			requests:    GlobalReqs,
			channels:    make(map[uint]*channel),
		}

		fmt.Println("new ssh connection from :", sshCon.RemoteAddr().String())
		go handleSshClint(clint)
	}
}

type sshClint struct {
	connection  ssh.ServerConn
	requests    <-chan *ssh.Request
	newChannels <-chan ssh.NewChannel
	channelsNum uint
	channels    map[uint]*channel
}

type channel struct {
	connection ssh.Channel
	requests   <-chan *ssh.Request
	id         uint
	clint      *sshClint
}

func handleSshClint(clint *sshClint) {
	defer clint.connection.Close()
	go ssh.DiscardRequests(clint.requests)

	for newChannel := range clint.newChannels {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "UnknownChannelType")
			continue
		}
		sshChannel, chanReqs, err := newChannel.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}

		clintChannel := &channel{
			connection: sshChannel,
			requests:   chanReqs,
			id:         clint.channelsNum,
			clint:      clint,
		}
		clint.channelsNum++
		go run(clintChannel)
	}
}

func run(channel *channel) {
	cmd := exec.Command(os.Args[2])
	pty, err := pty.Start(cmd)
	if err != nil {
		panic(err)
	}

	go handleChannelReqs(channel, pty)
	go io.Copy(channel.connection, pty)
	go io.Copy(pty, channel.connection)
	cmd.Wait()
	fmt.Printf("clint %v : close\n", channel.clint.connection.Conn.RemoteAddr())
	pty.Close()
	channel.connection.Close()
	delete(channel.clint.channels, channel.id)
	channel.clint.channelsNum--
}

func handleChannelReqs(channel *channel, pry *os.File) {
	for req := range channel.requests {
		switch req.Type {
		case "pty-req":
			// Accept PTY request
			slen := binary.BigEndian.Uint32(req.Payload)
			s := 4 + slen
			cols := binary.BigEndian.Uint32(req.Payload[s : s+4])
			rows := binary.BigEndian.Uint32(req.Payload[s+4 : s+8])
			size := &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)}
			pty.Setsize(pry, size)
			fmt.Printf("clint %v : Window size %v:%v \n", channel.clint.connection.Conn.RemoteAddr(), cols, rows)
			req.Reply(true, nil)
		case "shell":
			// Accept shell request
			req.Reply(true, nil)
		case "window-change":
			// Accept dynamic window-change request
			cols := binary.BigEndian.Uint32(req.Payload[0:4])
			rows := binary.BigEndian.Uint32(req.Payload[4:8])
			size := &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)}
			pty.Setsize(pry, size)
			fmt.Printf("Clint %v : Resize window %v:%v \n", channel.clint.connection.Conn.RemoteAddr(), cols, rows)
			req.Reply(true, nil)
		default:
			// Reject unknown requests
			req.Reply(false, nil)
		}
	}
}
