// +build cgo
// Copyright (c) 2020 Moriyoshi Koizumi
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
package main

// #include <sys/types.h>
// #include <string.h>
// #include <pwd.h>
// #include <grp.h>
// #include <shadow.h>
// #include <nss.h>
//
// size_t _GoStringLen(_GoString_ s);
// const char *_GoStringPtr(_GoString_ s);
//
// static inline void gostrcpy(char *dst, _GoString_ s) {
//     const size_t l = _GoStringLen(s);
//     memcpy(dst, _GoStringPtr(s), l);
//	   dst[l] = 0;
// }
import "C"

import (
	"context"
	"fmt"
	"hash/crc32"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/aws/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/iamiface"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const ttl = 120 * time.Second
const uidBase = 131072
const homeDirTemplate = "/home/%s"
const defaultShell = "/bin/sh"
const tagUid = "UnixUid"
const tagGid = "UnixGid"
const tagHomeDir = "UnixHomeDirectory"
const tagShell = "UnixShell"

var debugEnabled bool
var timeout time.Duration
var rootCtx = context.Background()

func init() {
	var err error
	debugEnabled = os.Getenv("NSS_AWSIAM_GO_DEBUG") != ""
	timeout, err = time.ParseDuration(os.Getenv("NSS_AWSIAM_GO_TIMEOUT"))
	if err != nil {
		timeout = time.Second * 3
	}
}

func debug(msg ...interface{}) {
	if debugEnabled {
		fmt.Fprintln(os.Stderr, msg...)
	}
}

func getAwsConfig() (cfg aws.Config, err error) {
	stsAssumeRoleArn := os.Getenv("AWS_STS_ASSUME_ROLE_ARN")
	if stsAssumeRoleArn != "" {
		var extraConfigs []external.Config
		stsSourceProfile := os.Getenv("AWS_STS_SOURCE_PROFILE")
		if stsSourceProfile != "" {
			extraConfigs = []external.Config{external.WithSharedConfigProfile(stsSourceProfile)}
		}
		cfg, err = external.LoadDefaultAWSConfig(extraConfigs...)
		if err != nil {
			return
		}
		sts := sts.New(cfg)
		cfg.Credentials = stscreds.NewAssumeRoleProvider(sts, stsAssumeRoleArn)
	} else {
		cfg, err = external.LoadDefaultAWSConfig()
		if err != nil {
			return
		}
	}
	return
}

var iamCli *iamClient = newIamClient(
	func() (iamiface.ClientAPI, error) {
		cfg, err := getAwsConfig()
		if err != nil {
			return nil, err
		}
		return iam.New(cfg), nil
	},
	time.Now,
)

type iamWrap struct {
	context.Context
	iamClient *iamClient
	timeout   time.Duration
}

func (iamw *iamWrap) getIamUser(name string) (*iam.User, error) {
	ctx, cancel := context.WithTimeout(iamw, iamw.timeout)
	defer cancel()
	return iamw.iamClient.getUser(ctx, name)
}

func (iamw *iamWrap) getIamUsers() ([]iam.User, error) {
	ctx, cancel := context.WithTimeout(iamw, iamw.timeout)
	defer cancel()
	return iamw.iamClient.listUsers(ctx)
}

func (iamw *iamWrap) getIamGroup(name string) (*iam.Group, []*iam.User, error) {
	ctx, cancel := context.WithTimeout(iamw, iamw.timeout)
	defer cancel()
	return iamw.iamClient.getGroup(ctx, name)
}

func (iamw *iamWrap) getIamGroups() ([]iam.Group, error) {
	ctx, cancel := context.WithTimeout(iamw, iamw.timeout)
	defer cancel()
	return iamw.iamClient.listGroups(ctx)
}

func (iamw *iamWrap) getIamUsersInGroup(name string) ([]*iam.User, error) {
	ctx, cancel := context.WithTimeout(iamw, iamw.timeout)
	defer cancel()
	return iamw.iamClient.getUsersInGroup(ctx, name)
}

func newIamWrap(ctx context.Context) *iamWrap {
	return &iamWrap{
		iamClient: iamCli,
		Context:   ctx,
		timeout:   timeout,
	}
}

type bufalloc struct {
	buf    uintptr
	buflen uintptr
}

func (a *bufalloc) alloc(l uintptr) (*C.char, bool) {
	if a.buflen < l {
		return nil, false
	}
	p := (*C.char)(unsafe.Pointer(a.buf))
	a.buf += l
	return p, true
}

func (a *bufalloc) allocPtrArray(l uintptr) ([]*C.char, bool) {
	sz := unsafe.Sizeof((*C.char)(nil)) * l
	if sz/unsafe.Sizeof((*C.char)(nil)) != l {
		return nil, false
	}
	if a.buflen < sz {
		return nil, false
	}
	p := (*[math.MaxInt32]*C.char)(unsafe.Pointer(a.buf))
	a.buf += sz
	return p[:l], true
}

func toUid(id string) int {
	return int(crc32.ChecksumIEEE([]byte(id)) >> 1)
}

var insufficientBuffer = fmt.Errorf("insufficient buffer")

func fillPwentWithIamUser(
	pwd *C.struct_passwd,
	b bufalloc,
	user *iam.User,
) error {
	// pw_name
	{
		p, ok := b.alloc(uintptr(len(*user.UserName) + 1))
		if !ok {
			return insufficientBuffer
		}
		C.gostrcpy(p, *user.UserName)
		pwd.pw_name = p
	}
	// pw_passwd
	{
		p, ok := b.alloc(1)
		if !ok {
			return insufficientBuffer
		}
		*p = 0
		pwd.pw_passwd = p
	}
	var uid, gid int
	var homeDir, shell string
	{
		for _, t := range user.Tags {
			var err error
			switch *t.Key {
			case tagUid:
				uid, err = strconv.Atoi(*t.Value)
				if err != nil {
					return err
				}
			case tagGid:
				gid, err = strconv.Atoi(*t.Value)
				if err != nil {
					gid = 0
				}
			case tagHomeDir:
				homeDir = *t.Value
			case tagShell:
				shell = *t.Value
			}
		}
	}
	if uid == 0 {
		uid = uidBase + toUid(*user.UserId)
	}
	if gid == 0 {
		gid = uid
	}
	pwd.pw_uid = C.uid_t(uid)
	pwd.pw_gid = C.gid_t(gid)
	if homeDir == "" {
		homeDir = fmt.Sprintf(homeDirTemplate, *user.UserName)
	}
	if shell == "" {
		shell = defaultShell
	}
	// pw_gecos
	{
		p, ok := b.alloc(uintptr(len(*user.Arn) + 1))
		if !ok {
			return insufficientBuffer
		}
		C.gostrcpy(p, strings.ReplaceAll((*user.Arn), ":", "-"))
		pwd.pw_gecos = p
	}
	// pw_dir
	{
		p, ok := b.alloc(uintptr(len(homeDir) + 1))
		if !ok {
			return insufficientBuffer
		}
		C.gostrcpy(p, homeDir)
		pwd.pw_dir = p
	}
	// pw_shell
	{
		p, ok := b.alloc(uintptr(len(shell) + 1))
		if !ok {
			return insufficientBuffer
		}
		C.gostrcpy(p, shell)
		pwd.pw_shell = p
	}
	return nil
}

//export _nss_awsiam_go_getpwnam_r
func _nss_awsiam_go_getpwnam_r(
	name *C.char,
	pwd *C.struct_passwd,
	buf *C.char,
	buflen C.size_t,
	result **C.struct_passwd,
) C.enum_nss_status {
	iamw := newIamWrap(rootCtx)
	goName := C.GoString(name)
	user, err := iamw.getIamUser(goName)
	if err != nil {
		debug("getpwnam_r", err)
		if err, ok := err.(awserr.RequestFailure); ok {
			if err.StatusCode() == 404 {
				return C.NSS_STATUS_NOTFOUND
			}
		}
		return C.NSS_STATUS_UNAVAIL
	}
	err = fillPwentWithIamUser(
		pwd,
		bufalloc{
			buf:    uintptr(unsafe.Pointer(buf)),
			buflen: uintptr(buflen),
		},
		user,
	)
	if err == insufficientBuffer {
		return C.NSS_STATUS_TRYAGAIN
	} else if err != nil {
		return C.NSS_STATUS_UNAVAIL
	}
	if result != nil {
		*result = pwd
	}
	return C.NSS_STATUS_SUCCESS
}

var getpwentContext struct {
	iamw  *iamWrap
	users []iam.User
	i     int
}

//export _nss_awsiam_go_setpwent
func _nss_awsiam_go_setpwent() {
	getpwentContext.iamw = nil
}

//export _nss_awsiam_go_endpwent
func _nss_awsiam_go_endpwent() {
	getpwentContext.iamw = nil
}

//export _nss_awsiam_go_getpwent_r
func _nss_awsiam_go_getpwent_r(pwbuf *C.struct_passwd, buf *C.char, buflen C.size_t, pwbufp **C.struct_passwd) C.enum_nss_status {
	if getpwentContext.iamw == nil {
		iamw := newIamWrap(rootCtx)
		users, err := iamw.getIamUsers()
		if err != nil {
			debug("getpwent_r", err)
			return C.NSS_STATUS_UNAVAIL
		}
		getpwentContext.iamw = iamw
		getpwentContext.users = users
		getpwentContext.i = 0
	}
	if getpwentContext.i >= len(getpwentContext.users) {
		getpwentContext.iamw = nil
		return C.NSS_STATUS_NOTFOUND
	}
	fillPwentWithIamUser(
		pwbuf,
		bufalloc{
			buf:    uintptr(unsafe.Pointer(buf)),
			buflen: uintptr(buflen),
		},
		&getpwentContext.users[getpwentContext.i],
	)
	getpwentContext.i += 1
	return C.NSS_STATUS_SUCCESS
}

func fillGrentWithIamGroup(
	gr *C.struct_group,
	b bufalloc,
	group *iam.Group,
	members []*iam.User,
) error {
	// gr_name
	{
		p, ok := b.alloc(uintptr(len(*group.GroupName) + 1))
		if !ok {
			return insufficientBuffer
		}
		C.gostrcpy(p, *group.GroupName)
		gr.gr_name = p
	}
	// gr_passwd
	{
		p, ok := b.alloc(1)
		if !ok {
			return insufficientBuffer
		}
		*p = 0
		gr.gr_passwd = p
	}
	gr.gr_gid = C.gid_t(uidBase + toUid(*group.GroupId))
	// gr_mem
	{
		pp, ok := b.allocPtrArray(uintptr(len(members) + 1))
		if !ok {
			return insufficientBuffer
		}
		for i, m := range members {
			p, ok := b.alloc(uintptr(len(*m.UserName) + 1))
			if !ok {
				return insufficientBuffer
			}
			C.gostrcpy(p, *m.UserName)
			pp[i] = p
		}
		pp[len(members)] = nil
		gr.gr_mem = &pp[0]
	}
	return nil
}

//export _nss_awsiam_go_getgrnam_r
func _nss_awsiam_go_getgrnam_r(
	name *C.char,
	grp *C.struct_group,
	buf *C.char,
	buflen C.size_t,
	result **C.struct_group,
) C.enum_nss_status {
	iamw := newIamWrap(rootCtx)
	goName := C.GoString(name)
	group, members, err := iamw.getIamGroup(goName)
	if err != nil {
		debug("getgrnam_r", err)
		if err, ok := err.(awserr.RequestFailure); ok {
			if err.StatusCode() == 404 {
				return C.NSS_STATUS_NOTFOUND
			}
		}
		return C.NSS_STATUS_UNAVAIL
	}
	err = fillGrentWithIamGroup(
		grp,
		bufalloc{
			buf:    uintptr(unsafe.Pointer(buf)),
			buflen: uintptr(buflen),
		},
		group,
		members,
	)
	if err == insufficientBuffer {
		return C.NSS_STATUS_TRYAGAIN
	} else if err != nil {
		return C.NSS_STATUS_UNAVAIL
	}
	if result != nil {
		*result = grp
	}
	return C.NSS_STATUS_SUCCESS
}

var getgrentContext struct {
	iamw   *iamWrap
	groups []iam.Group
	i      int
}

//export _nss_awsiam_go_setgrent
func _nss_awsiam_go_setgrent() {
	getgrentContext.iamw = nil
}

//export _nss_awsiam_go_endgrent
func _nss_awsiam_go_endgrent() {
	getgrentContext.iamw = nil
}

//export _nss_awsiam_go_getgrent_r
func _nss_awsiam_go_getgrent_r(grbuf *C.struct_group, buf *C.char, buflen C.size_t, grbufp **C.struct_group) C.enum_nss_status {
	if getgrentContext.iamw == nil {
		iamw := newIamWrap(rootCtx)
		groups, err := iamw.getIamGroups()
		if err != nil {
			debug("getgrent_r", err)
			return C.NSS_STATUS_UNAVAIL
		}
		getgrentContext.iamw = iamw
		getgrentContext.groups = groups
		getgrentContext.i = 0
	}
	if getgrentContext.i >= len(getgrentContext.groups) {
		getgrentContext.iamw = nil
		return C.NSS_STATUS_NOTFOUND
	}
	group := &getgrentContext.groups[getgrentContext.i]
	usersInGroup, err := getgrentContext.iamw.getIamUsersInGroup(*group.GroupName)
	if err != nil {
		debug("getgrent_r", err)
		return C.NSS_STATUS_UNAVAIL
	}
	fillGrentWithIamGroup(
		grbuf,
		bufalloc{
			buf:    uintptr(unsafe.Pointer(buf)),
			buflen: uintptr(buflen),
		},
		group,
		usersInGroup,
	)
	getgrentContext.i += 1
	return C.NSS_STATUS_SUCCESS
}

func fillSpentWithIamUser(
	spwd *C.struct_spwd,
	b bufalloc,
	user *iam.User,
) error {
	// pw_name
	{
		p, ok := b.alloc(uintptr(len(*user.UserName) + 1))
		if !ok {
			return insufficientBuffer
		}
		C.gostrcpy(p, *user.UserName)
		spwd.sp_namp = p
	}
	// pw_passwd
	{
		p, ok := b.alloc(1)
		if !ok {
			return insufficientBuffer
		}
		*p = 0
		spwd.sp_pwdp = p
	}
	spwd.sp_lstchg = 0
	spwd.sp_min = 0
	spwd.sp_max = 0
	spwd.sp_warn = 0
	spwd.sp_inact = 0
	spwd.sp_expire = 0
	return nil
}

//export _nss_awsiam_go_getspnam_r
func _nss_awsiam_go_getspnam_r(name *C.char, spbuf *C.struct_spwd, buf *C.char, buflen C.size_t, spbufp **C.struct_spwd) C.enum_nss_status {
	iamw := newIamWrap(rootCtx)
	goName := C.GoString(name)
	user, err := iamw.getIamUser(goName)
	if err != nil {
		debug("getspnam_r", err)
		if err, ok := err.(awserr.RequestFailure); ok {
			if err.StatusCode() == 404 {
				return C.NSS_STATUS_NOTFOUND
			}
		}
		return C.NSS_STATUS_UNAVAIL
	}
	err = fillSpentWithIamUser(
		spbuf,
		bufalloc{
			buf:    uintptr(unsafe.Pointer(buf)),
			buflen: uintptr(buflen),
		},
		user,
	)
	if err == insufficientBuffer {
		return C.NSS_STATUS_TRYAGAIN
	} else if err != nil {
		return C.NSS_STATUS_UNAVAIL
	}
	if spbufp != nil {
		*spbufp = spbuf
	}
	return C.NSS_STATUS_SUCCESS
}

func main() {
	fmt.Println("START")
}
