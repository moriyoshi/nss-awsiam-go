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
// #include <stdlib.h>
// #include <pwd.h>
// #include <grp.h>
// #include <shadow.h>
// #include <nss.h>
// #include <errno.h>
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
	"github.com/aws/aws-sdk-go-v2/aws/endpoints"
	"github.com/aws/aws-sdk-go-v2/aws/external"
	"github.com/aws/aws-sdk-go-v2/aws/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/iamiface"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/joho/godotenv"
)

const ttl = 120 * time.Second
const uidBase = 131072
const tagUid = "UnixUid"
const tagGid = "UnixGid"
const tagHomeDir = "UnixHomeDirectory"
const tagShell = "UnixShell"
const configFile = "/etc/nss_awsiam_go.conf"
const envNamePrefixEndpointOverride = "AWS_ENDPOINT_OVERRIDES_"

var debugLevel int = 0
var timeout time.Duration = 3 * time.Second
var homeDirTemplate = "/home/{userName}"
var defaultShell = "/bin/sh"
var rootCtx = context.Background()
var envMap map[string]string

func getenv(name string) string {
	if envMap != nil {
		v, ok := envMap[name]
		if ok {
			return v
		}
	}
	return ""
}

func getenvOfAny(names ...string) string {
	for _, name := range names {
		v := getenv(name)
		if v != "" {
			return v
		}
	}
	return ""
}

func init() {
	envMap, _ = godotenv.Read(configFile)
	populateConfigFromEnvVars()
}

func debug(msg ...interface{}) {
	if debugLevel > 0 {
		fmt.Fprintln(os.Stderr, msg...)
	}
}

func populateConfigFromEnvVars() {
	{
		v, err := strconv.Atoi(getenv("NSS_AWSIAM_GO_DEBUG"))
		if err == nil {
			debugLevel = v
		}
	}
	{
		v, err := time.ParseDuration(getenv("NSS_AWSIAM_GO_TIMEOUT"))
		if err == nil {
			timeout = v
		}
	}
	{
		v := getenv("NSS_AWSIAM_GO_HOMEDIR_TEMPLATE")
		if v != "" {
			homeDirTemplate = v
		}
	}
	{
		v := getenv("NSS_AWSIAM_GO_DEFAULT_SHELL")
		if v != "" {
			defaultShell = v
		}
	}
}

func boolVal(v string) (*bool, error) {
	v = strings.ToLower(v)
	if v == "false" {
		return aws.Bool(false), nil
	} else if v == "true" {
		return aws.Bool(true), nil
	} else {
		return nil, fmt.Errorf("\"true\" or \"false\" wanted, got %s", v)
	}
}

func envConfig(_ external.Configs) (external.Config, error) {
	var cfg external.EnvConfig
	var err error

	creds := aws.Credentials{
		Source: external.CredentialsSourceName,
	}
	creds.AccessKeyID = getenvOfAny("AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY")
	creds.SecretAccessKey = getenvOfAny("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY")
	if creds.HasKeys() {
		creds.SessionToken = getenvOfAny("AWS_SESSION_TOKEN")
		cfg.Credentials = creds
	}

	cfg.ContainerCredentialsEndpoint = getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
	cfg.ContainerCredentialsRelativePath = getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
	cfg.ContainerAuthorizationToken = getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")

	cfg.Region = getenvOfAny("AWS_REGION", "AWS_DEFAULT_REGION")
	cfg.SharedConfigProfile = getenvOfAny("AWS_PROFILE", "AWS_DEFAULT_PROFILE")

	cfg.SharedCredentialsFile = getenv("AWS_SHARED_CREDENTIALS_FILE")
	cfg.SharedConfigFile = getenv("AWS_CONFIG_FILE")

	cfg.CustomCABundle = getenv("AWS_CA_BUNDLE")

	cfg.WebIdentityTokenFilePath = getenv("AWS_WEB_IDENTITY_TOKEN_FILE")

	cfg.RoleARN = getenv("AWS_ROLE_ARN")
	cfg.RoleSessionName = getenv("AWS_ROLE_SESSION_NAME")

	if v := getenv("AWS_ENABLE_ENDPOINT_DISCOVERY"); v != "" {
		cfg.EnableEndpointDiscovery, err = boolVal(v)
		if err != nil {
			return cfg, err
		}
	}
	if v := getenv("AWS_S3_USE_ARN_REGION"); v != "" {
		cfg.S3UseARNRegion, err = boolVal(v)
		if err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

func getAwsConfig() (cfg aws.Config, err error) {
	var ourConfigs external.Configs
	ourConfigs, _ = ourConfigs.AppendFromLoaders([]external.ConfigLoader{envConfig})
	stsAssumeRoleArn := getenv("AWS_STS_ASSUME_ROLE_ARN")
	if stsAssumeRoleArn != "" {
		cfg, err = ourConfigs.ResolveAWSConfig(external.DefaultAWSConfigResolvers)
		if err != nil {
			return
		}
		if debugLevel > 1 {
			cfg.LogLevel = aws.LogDebug
		}
		sts := sts.New(cfg)
		cfg.Credentials = stscreds.NewAssumeRoleProvider(sts, stsAssumeRoleArn)
	} else {
		cfg, err = ourConfigs.ResolveAWSConfig(external.DefaultAWSConfigResolvers)
		if err != nil {
			return
		}
		if debugLevel > 1 {
			cfg.LogLevel = aws.LogDebug
		}
	}

	resolver := endpoints.NewDefaultResolver()

	vars := map[string]string{
		"region": cfg.Region,
	}

	cfg.EndpointResolver = aws.EndpointResolverFunc(
		func(service, region string) (aws.Endpoint, error) {
			endpointTemplate := getenv(envNamePrefixEndpointOverride + strings.ToUpper(service))
			if endpointTemplate != "" {
				url, err := replacePlaceholders(endpointTemplate, vars)
				if err != nil {
					return aws.Endpoint{}, err
				}
				return aws.Endpoint{
					URL: url,
				}, nil
			} else {
				return resolver.ResolveEndpoint(service, region)
			}
		},
	)

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
		var err error
		vars := map[string]string{
			"userName": *user.UserName,
			"userId":   *user.UserId,
			"uid":      strconv.Itoa(uid),
		}
		homeDir, err = replacePlaceholders(homeDirTemplate, vars)
		if err != nil {
			return err
		}
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
		debug("getpwnam_r", err)
		return C.NSS_STATUS_UNAVAIL
	}
	if result != nil {
		*result = pwd
	}
	return C.NSS_STATUS_SUCCESS
}

//export _nss_awsiam_go_getpwuid_r
func _nss_awsiam_go_getpwuid_r(
	uid C.uid_t,
	pwd *C.struct_passwd,
	buf *C.char,
	buflen C.size_t,
	result **C.struct_passwd,
) C.enum_nss_status {
	iamw := newIamWrap(rootCtx)
	users, err := iamw.getIamUsers()
	if err != nil {
		debug("getpwuid_r", err)
		if err, ok := err.(awserr.RequestFailure); ok {
			if err.StatusCode() == 404 {
				return C.NSS_STATUS_NOTFOUND
			}
		}
		return C.NSS_STATUS_UNAVAIL
	}
	for _, user := range users {
		if uid == C.uid_t(uidBase+toUid(*user.UserId)) {
			err = fillPwentWithIamUser(
				pwd,
				bufalloc{
					buf:    uintptr(unsafe.Pointer(buf)),
					buflen: uintptr(buflen),
				},
				&user,
			)
			if err == insufficientBuffer {
				return C.NSS_STATUS_TRYAGAIN
			} else if err != nil {
				debug("getpwuid_r", err)
				return C.NSS_STATUS_UNAVAIL
			}
			if result != nil {
				*result = pwd
			}
			return C.NSS_STATUS_SUCCESS
		}
	}
	return C.NSS_STATUS_NOTFOUND
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

func fillGrentWithIamUser(
	gr *C.struct_group,
	b bufalloc,
	user *iam.User,
) error {
	// gr_name
	{
		p, ok := b.alloc(uintptr(len(*user.UserName) + 1))
		if !ok {
			return insufficientBuffer
		}
		C.gostrcpy(p, *user.UserName)
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
	gr.gr_gid = C.gid_t(uidBase + toUid(*user.UserId))
	// gr_mem
	{
		pp, ok := b.allocPtrArray(uintptr(1))
		if !ok {
			return insufficientBuffer
		}
		pp[0] = nil
		gr.gr_mem = &pp[0]
	}
	return nil
}

func gwnamPseudo(
	name string,
	iamw *iamWrap,
	grp *C.struct_group,
	buf *C.char,
	buflen C.size_t,
	result **C.struct_group,
) C.enum_nss_status {
	user, err := iamw.getIamUser(name)
	if err != nil {
		if err, ok := err.(awserr.RequestFailure); ok {
			if err.StatusCode() == 404 {
				return C.NSS_STATUS_NOTFOUND
			}
		}
		debug("getgrnam_r", err)
		return C.NSS_STATUS_UNAVAIL
	}
	err = fillGrentWithIamUser(
		grp,
		bufalloc{
			buf:    uintptr(unsafe.Pointer(buf)),
			buflen: uintptr(buflen),
		},
		user,
	)
	if err == insufficientBuffer {
		return C.NSS_STATUS_TRYAGAIN
	} else if err != nil {
		debug("getgrnam_r", err)
		return C.NSS_STATUS_UNAVAIL
	}
	if result != nil {
		*result = grp
	}
	return C.NSS_STATUS_SUCCESS
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
				return gwnamPseudo(goName, iamw, grp, buf, buflen, result)
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
		debug("getgrnam_r", err)
		return C.NSS_STATUS_UNAVAIL
	}
	if result != nil {
		*result = grp
	}
	return C.NSS_STATUS_SUCCESS
}

//export _nss_awsiam_go_getgrgid_r
func _nss_awsiam_go_getgrgid_r(
	gid C.gid_t,
	grp *C.struct_group,
	buf *C.char,
	buflen C.size_t,
	result **C.struct_group,
) C.enum_nss_status {
	iamw := newIamWrap(rootCtx)
	groups, err := iamw.getIamGroups()
	if err != nil {
		debug("getgrgid_r", err)
		if err, ok := err.(awserr.RequestFailure); ok {
			if err.StatusCode() == 404 {
				goto scanPseudoGroups
			}
		}
		return C.NSS_STATUS_UNAVAIL
	}
	for _, group := range groups {
		if gid == C.gid_t(uidBase+toUid(*group.GroupId)) {
			members, err := iamw.getIamUsersInGroup(*group.GroupName)
			if err != nil {
				debug("getgrgid_r", err)
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
				&group,
				members,
			)
			if err == insufficientBuffer {
				return C.NSS_STATUS_TRYAGAIN
			} else if err != nil {
				debug("getgrgid_r", err)
				return C.NSS_STATUS_UNAVAIL
			}
			if result != nil {
				*result = grp
			}
			return C.NSS_STATUS_SUCCESS
		}
	}

scanPseudoGroups:
	users, err := iamw.getIamUsers()
	if err != nil {
		debug("getgrgid_r", err)
		if err, ok := err.(awserr.RequestFailure); ok {
			if err.StatusCode() == 404 {
				return C.NSS_STATUS_NOTFOUND
			}
		}
		return C.NSS_STATUS_UNAVAIL
	}
	for _, user := range users {
		if gid == C.gid_t(uidBase+toUid(*user.UserId)) {
			err = fillGrentWithIamUser(
				grp,
				bufalloc{
					buf:    uintptr(unsafe.Pointer(buf)),
					buflen: uintptr(buflen),
				},
				&user,
			)
			if err == insufficientBuffer {
				return C.NSS_STATUS_TRYAGAIN
			} else if err != nil {
				debug("getgwgid_r", err)
				return C.NSS_STATUS_UNAVAIL
			}
			if result != nil {
				*result = grp
			}
			return C.NSS_STATUS_SUCCESS
		}
	}
	return C.NSS_STATUS_NOTFOUND
}

var getgrentContext struct {
	iamw   *iamWrap
	groups []iam.Group
	users  []iam.User
	i, j   int
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
		users, err := iamw.getIamUsers()
		if err != nil {
			debug("getgrent_r", err)
			return C.NSS_STATUS_UNAVAIL
		}
		getgrentContext.iamw = iamw
		getgrentContext.groups = groups
		getgrentContext.users = users
		getgrentContext.i = 0
		getgrentContext.j = 0
	}
	if getgrentContext.i < len(getgrentContext.groups) {
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
	if getgrentContext.j < len(getgrentContext.users) {
		user := &getgrentContext.users[getgrentContext.j]
		fillGrentWithIamUser(
			grbuf,
			bufalloc{
				buf:    uintptr(unsafe.Pointer(buf)),
				buflen: uintptr(buflen),
			},
			user,
		)
		getgrentContext.j += 1
		return C.NSS_STATUS_SUCCESS
	}
	getgrentContext.iamw = nil
	return C.NSS_STATUS_NOTFOUND
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
		debug("getspnam_r", err)
		return C.NSS_STATUS_UNAVAIL
	}
	if spbufp != nil {
		*spbufp = spbuf
	}
	return C.NSS_STATUS_SUCCESS
}

type initgroupsBuf struct {
	i     uintptr
	size  uintptr
	limit uintptr
	buf   *C.gid_t
}

func (a *initgroupsBuf) add(item C.gid_t) (bool, bool) {
	if a.i >= a.size {
		if a.limit != 0 && a.size >= a.limit {
			return true, false
		} else {
			newSize := 2 * a.size
			if newSize/a.size < 2 {
				// overflow
				return false, true
			}
			if a.limit != 0 && newSize > a.limit {
				newSize = a.limit
			}
			newSizeInBytes := newSize * unsafe.Sizeof(C.gid_t(0))
			if newSizeInBytes/newSize < unsafe.Sizeof(C.gid_t(0)) {
				// overflow
				return false, true
			}
			newBuf := C.realloc(unsafe.Pointer(a.buf), C.size_t(newSizeInBytes))
			if newBuf == nil {
				return false, true
			}
			a.buf = (*C.gid_t)(newBuf)
			a.size = newSize
		}
	}
	p := (*[math.MaxInt32]C.gid_t)(unsafe.Pointer(a.buf))
	p[a.i] = item
	a.i += 1
	return false, false
}

//export _nss_awsiam_go_initgroups_dyn
func _nss_awsiam_go_initgroups_dyn(name *C.char, exclude C.gid_t, start *C.long, size *C.long, groupsp **C.gid_t, limit C.long, errnop *C.int) C.enum_nss_status {
	if *start < 0 {
		debug("initgroups_dyn: *start < 0")
		return C.NSS_STATUS_UNAVAIL
	}
	if *size < 0 {
		debug("initgroups_dyn: *size < 0")
		return C.NSS_STATUS_UNAVAIL
	}
	if *start >= *size {
		debug("initgroups_dyn: *start >= *size")
		return C.NSS_STATUS_UNAVAIL
	}
	if groupsp == nil {
		debug("initgroups_dyn: groupsp == nil")
		return C.NSS_STATUS_UNAVAIL
	}
	iamw := newIamWrap(rootCtx)
	goName := C.GoString(name)
	groups, err := iamw.getIamGroups()
	if err != nil {
		debug("initgroups_dyn", err)
		return C.NSS_STATUS_UNAVAIL
	}
	if limit < 0 {
		limit = 0
	}
	b := initgroupsBuf{
		i:     uintptr(*start), // validated; safe
		size:  uintptr(*size),  // validated; safe
		limit: uintptr(limit),  // negative value coerced; safe
		buf:   *groupsp,
	}

outer:
	for _, g := range groups {
		gid := C.gid_t(uidBase + toUid(*g.GroupId))
		if gid == exclude {
			continue
		}
		users, err := iamw.getIamUsersInGroup(*g.GroupName)
		if err != nil {
			debug("initgroups_dyn", err)
			return C.NSS_STATUS_UNAVAIL
		}
		for _, u := range users {
			if *u.UserName == goName {
				limitReached, badAlloc := b.add(gid)
				if limitReached {
					break outer
				} else if badAlloc {
					err = insufficientBuffer
					break outer
				}
			}
		}
	}
	// sync back
	*groupsp = b.buf // this must always be sync
	if b.i > uintptr(1<<(8*unsafe.Sizeof(C.long(0))-1)-1) {
		return C.NSS_STATUS_UNAVAIL
	}
	*start = C.long(b.i)
	if b.size > uintptr(1<<(8*unsafe.Sizeof(C.long(0))-1)-1) {
		return C.NSS_STATUS_UNAVAIL
	}
	*size = C.long(b.size)

	if err == insufficientBuffer {
		return C.NSS_STATUS_TRYAGAIN
	} else if err != nil {
		debug("initgroups_dyn", err)
		return C.NSS_STATUS_UNAVAIL
	}
	return C.NSS_STATUS_SUCCESS
}

func main() {
}
