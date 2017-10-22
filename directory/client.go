package directory

import (
	"golang.org/x/oauth2/jwt"
	"encoding/json"
	"log"
	"google.golang.org/api/admin/directory/v1"
	"context"
)

type Client struct {
	directoryService *admin.Service
	customerId       string
	domain           string
}

func New(credentials []byte, subject string, customerId string, domain string) (*Client, error) {
	var credentialsMap map[string]string
	err := json.Unmarshal(credentials, &credentialsMap)
	if err != nil {
		log.Fatalf("failed to unmarshal credentials: %v", err)
		return nil, err
	}

	config := &jwt.Config{
		Email:        string(credentialsMap["client_email"]),
		PrivateKey:   []byte(credentialsMap["private_key"]),
		PrivateKeyID: string(credentialsMap["private_key_id"]),
		Scopes:       []string{admin.AdminDirectoryGroupReadonlyScope, admin.AdminDirectoryGroupMemberReadonlyScope},
		TokenURL:     string(credentialsMap["token_uri"]),
		Subject:      subject,
	}

	httpClient := config.Client(context.Background())

	service, err := admin.New(httpClient)
	if err != nil {
		log.Fatalf("unable to retrieve directory service: %v", err)
		return nil, err
	}

	return &Client{
		directoryService: service,
		customerId:       customerId,
		domain:           domain,
	}, nil
}

func (c *Client) RetrieveDirectory() (map[string]*Group, error) {
	groups, err := c.retrieveGroups()
	if err != nil {
		return nil, err
	}

	for _, group := range groups {
		members, err := c.retrieveMembers(group.Id)
		if err != nil {
			return nil, err
		}
		group.Members = members
	}

	return groups, nil
}

func ToMemberGroupMapping(groups map[string]*Group) map[string][]string {
	members := map[string][]string{}

	for _, group := range groups {
		updateMemberMap(members, groups, group, group.Id)
	}

	return members
}

func updateMemberMap(members map[string][]string, groups map[string]*Group, group *Group, groupId string) {
	for memberId, _ := range group.Members {
		if _, ok := groups[memberId]; ok {
			updateMemberMap(members, groups, groups[memberId], groupId)
		} else {
			if groups, ok := members[memberId]; ok {
				members[memberId] = appendUnique(groups, groupId)
			} else {
				members[memberId] = []string{groupId}
			}
		}
	}
}

func appendUnique(groupIds []string, groupId string) []string {
	for _, id := range groupIds {
		if id == groupId {
			return groupIds
		}
	}
	return append(groupIds, groupId)
}

func ToEmailGroupMapping(groups map[string]*Group) map[string]string {
	emails := map[string]string{}
	for id, group := range groups {
		emails[group.Email] = id
		for _, alias := range group.Aliases {
			emails[alias] = id
		}
	}
	return emails
}