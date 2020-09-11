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

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/iamiface"
)

type userCacheEntry struct {
	expiry time.Time
	data   *iam.User
}

type groupCacheEntry struct {
	expiry  time.Time
	data    *iam.Group
	members []*iam.User
}

type groupsForUserCacheEntry struct {
	expiry time.Time
	data   []iam.Group
}

type iamClient struct {
	mu            sync.Mutex
	clientBuilder func() (iamiface.ClientAPI, error)
	nowGetter     func() time.Time
	client        iamiface.ClientAPI

	userCache          map[string]userCacheEntry
	groupCache         map[string]groupCacheEntry
	groupsForUserCache map[string]groupsForUserCacheEntry
	listUsersCache     struct {
		expiry time.Time
		data   []iam.User
	}
	listGroupsCache struct {
		expiry time.Time
		data   []iam.Group
	}
	// groupMembersCache struct {
	// 	expiry time.Time
	// 	data   map[string][]*iam.User
	// }
}

func (cli *iamClient) getIamClient() (iamiface.ClientAPI, error) {
	if cli.client == nil {
		client, err := cli.clientBuilder()
		if err != nil {
			return nil, err
		}
		cli.client = client
	}
	return cli.client, nil
}

func (cli *iamClient) listUsers(ctx context.Context) ([]iam.User, error) {
	cli.mu.Lock()
	defer cli.mu.Unlock()
	var retval []iam.User
	if !cli.listUsersCache.expiry.IsZero() &&
		cli.listUsersCache.expiry.After(cli.nowGetter()) {
		retval = cli.listUsersCache.data
	} else {
		var marker *string
		client, err := cli.getIamClient()
		if err != nil {
			return nil, err
		}
		for {
			req := client.ListUsersRequest(
				&iam.ListUsersInput{
					Marker: marker,
				},
			)
			resp, err := req.Send(ctx)
			if err != nil {
				return nil, err
			}
			retval = append(retval, resp.Users...)
			if resp.IsTruncated != nil {
				if !*resp.IsTruncated {
					break
				} else {
					if resp.Marker == nil {
						return nil, fmt.Errorf("resp.IsTruncated is true, but no marker is given")
					}
					marker = resp.Marker
				}
			}
		}
		expiry := cli.nowGetter().Add(ttl)
		for _, user := range retval {
			cli.userCache[*user.UserName] = userCacheEntry{
				expiry: expiry,
				data:   &user,
			}
		}
		cli.listUsersCache.data = retval
		cli.listUsersCache.expiry = expiry
	}
	return retval, nil
}

func (cli *iamClient) listGroups(ctx context.Context) ([]iam.Group, error) {
	cli.mu.Lock()
	defer cli.mu.Unlock()
	var retval []iam.Group
	if !cli.listGroupsCache.expiry.IsZero() &&
		cli.listGroupsCache.expiry.After(cli.nowGetter()) {
		retval = cli.listGroupsCache.data
	} else {
		var marker *string
		client, err := cli.getIamClient()
		if err != nil {
			return nil, err
		}
		for {
			req := client.ListGroupsRequest(
				&iam.ListGroupsInput{
					Marker: marker,
				},
			)
			resp, err := req.Send(ctx)
			if err != nil {
				return nil, err
			}
			retval = append(retval, resp.Groups...)
			if resp.IsTruncated != nil {
				if !*resp.IsTruncated {
					break
				} else {
					if resp.Marker == nil {
						return nil, fmt.Errorf("resp.IsTruncated is true, but no marker is given")
					}
					marker = resp.Marker
				}
			}
		}
		expiry := cli.nowGetter().Add(ttl)
		for _, group := range retval {
			cli.groupCache[*group.GroupName] = groupCacheEntry{
				expiry:  expiry,
				data:    &group,
				members: nil,
			}
		}
		cli.listGroupsCache.data = retval
		cli.listGroupsCache.expiry = expiry
	}
	return retval, nil
}

func (cli *iamClient) listGroupsForUser(ctx context.Context, userName string) ([]iam.Group, error) {
	cli.mu.Lock()
	defer cli.mu.Unlock()
	var retval []iam.Group
	ent, ok := cli.groupsForUserCache[userName]
	if ok && ent.expiry.IsZero() && ent.expiry.After(cli.nowGetter()) {
		retval = ent.data
	} else {
		var marker *string
		client, err := cli.getIamClient()
		if err != nil {
			return nil, err
		}
		for {
			req := client.ListGroupsForUserRequest(
				&iam.ListGroupsForUserInput{
					Marker:   marker,
					UserName: &userName,
				},
			)
			resp, err := req.Send(ctx)
			if err != nil {
				return nil, err
			}
			retval = append(retval, resp.Groups...)
			if resp.IsTruncated != nil {
				if !*resp.IsTruncated {
					break
				} else {
					if resp.Marker == nil {
						return nil, fmt.Errorf("resp.IsTruncated is true, but no marker is given")
					}
					marker = resp.Marker
				}
			}
		}
		expiry := cli.nowGetter().Add(ttl)
		for _, group := range retval {
			cli.groupCache[*group.GroupName] = groupCacheEntry{
				expiry:  expiry,
				data:    &group,
				members: nil,
			}
		}
		cli.groupsForUserCache[userName] = groupsForUserCacheEntry{
			expiry: expiry,
			data:   retval,
		}
	}
	return retval, nil
}

func (cli *iamClient) getUser(ctx context.Context, userName string) (*iam.User, error) {
	cli.mu.Lock()
	defer cli.mu.Unlock()
	var retval *iam.User
	ent, ok := cli.userCache[userName]
	if ok && ent.expiry.IsZero() && ent.expiry.After(cli.nowGetter()) {
		retval = ent.data
	} else {
		client, err := cli.getIamClient()
		if err != nil {
			return nil, err
		}
		req := client.GetUserRequest(
			&iam.GetUserInput{
				UserName: &userName,
			},
		)
		resp, err := req.Send(ctx)
		if err != nil {
			return nil, err
		}
		retval = resp.User
		cli.userCache[userName] = userCacheEntry{
			expiry: cli.nowGetter().Add(ttl),
			data:   retval,
		}
	}
	return retval, nil
}

func (cli *iamClient) getGroup(ctx context.Context, groupName string) (*iam.Group, []*iam.User, error) {
	cli.mu.Lock()
	defer cli.mu.Unlock()
	var group *iam.Group
	var members []*iam.User
	ent, ok := cli.groupCache[groupName]
	if ok && ent.expiry.IsZero() && ent.expiry.After(cli.nowGetter()) && ent.members != nil {
		group = ent.data
		members = ent.members
	} else {
		var marker *string
		expiry := cli.nowGetter().Add(ttl)
		client, err := cli.getIamClient()
		if err != nil {
			return nil, nil, err
		}
		for {
			req := client.GetGroupRequest(
				&iam.GetGroupInput{
					Marker:    marker,
					GroupName: &groupName,
				},
			)
			resp, err := req.Send(ctx)
			if err != nil {
				return nil, nil, err
			}
			for _, user := range resp.Users {
				_user := new(iam.User)
				*_user = user
				cli.userCache[*user.UserName] = userCacheEntry{
					expiry: expiry,
					data:   _user,
				}
				members = append(members, _user)
			}
			if resp.IsTruncated != nil {
				if !*resp.IsTruncated {
					group = resp.Group
					break
				} else {
					if resp.Marker == nil {
						return nil, nil, fmt.Errorf("resp.IsTruncated is true, but no marker is given")
					}
					marker = resp.Marker
				}
			}
		}
		cli.groupCache[groupName] = groupCacheEntry{
			expiry:  expiry,
			data:    group,
			members: members,
		}
	}
	return group, members, nil
}

/*
func (cli *iamClient) getGroupMembersMap(ctx context.Context) (map[string][]*iam.User, error) {
	cli.mu.Lock()
	defer cli.mu.Unlock()
	var retval map[string][]*iam.User
	if !cli.groupMembersCache.expiry.IsZero() &&
		cli.groupMembersCache.expiry.After(cli.nowGetter()) {
		retval = cli.groupMembersCache.data
	} else {
		users, err := cli.listUsers(ctx)
		if err != nil {
			return nil, err
		}
		var expiry time.Time
		for _, user := range users {
			groups, err := cli.listGroupsForUser(ctx, *user.UserName)
			if err != nil {
				return nil, err
			}
			ent := cli.groupsForUserCache[*user.UserName]
			if expiry.IsZero() || expiry.After(ent.expiry) {
				expiry = ent.expiry
			}
			for _, group := range groups {
				retval[*group.GroupName] = append(retval[*group.GroupName], &user)
			}
		}
		if expiry.IsZero() || expiry.After(cli.listUsersCache.expiry) {
			expiry = cli.listUsersCache.expiry
		}
		cli.groupMembersCache.expiry = expiry
		cli.groupMembersCache.data = retval
	}
	return retval, nil
}
*/
func (cli *iamClient) getUsersInGroup(ctx context.Context, groupName string) ([]*iam.User, error) {
	_, members, err := cli.getGroup(ctx, groupName)
	if err != nil {
		return nil, err
	}
	return members, nil
}

func newIamClient(clientBuilder func() (iamiface.ClientAPI, error), nowGetter func() time.Time) *iamClient {
	return &iamClient{
		clientBuilder:      clientBuilder,
		nowGetter:          nowGetter,
		userCache:          make(map[string]userCacheEntry),
		groupCache:         make(map[string]groupCacheEntry),
		groupsForUserCache: make(map[string]groupsForUserCacheEntry),
	}
}
