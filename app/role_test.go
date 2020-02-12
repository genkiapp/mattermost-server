// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package app

import (
	"encoding/csv"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/mattermost/mattermost-server/v5/model"
	"github.com/mattermost/mattermost-server/v5/utils/slices"
	"github.com/stretchr/testify/require"
)

type permissionInheritanceTestData struct {
	channelRole          *model.Role
	permission           *model.Permission
	shouldHavePermission bool
	channel              *model.Channel
	higherScopedRole     *model.Role
	truthTableRow        []string
}

func TestGetRolesByNames(t *testing.T) {
	testPermissionInheritance(t, func(t *testing.T, th *TestHelper, testData permissionInheritanceTestData) {
		actualRoles, err := th.App.GetRolesByNames([]string{testData.channelRole.Name})
		require.Nil(t, err)
		require.Len(t, actualRoles, 1)

		actualRole := actualRoles[0]
		require.NotNil(t, actualRole)
		require.Equal(t, testData.channelRole.Name, actualRole.Name)

		require.Equal(t, testData.shouldHavePermission, slices.IncludesString(actualRole.Permissions, testData.permission.Id))
	})
}

func TestGetRoleByName(t *testing.T) {
	testPermissionInheritance(t, func(t *testing.T, th *TestHelper, testData permissionInheritanceTestData) {
		actualRole, err := th.App.GetRoleByName(testData.channelRole.Name)
		require.Nil(t, err)
		require.NotNil(t, actualRole)
		require.Equal(t, testData.channelRole.Name, actualRole.Name)
		require.Equal(t, testData.shouldHavePermission, slices.IncludesString(actualRole.Permissions, testData.permission.Id))
	})
}

func testPermissionInheritance(t *testing.T, testCallback func(t *testing.T, th *TestHelper, testData permissionInheritanceTestData)) {
	th := Setup(t).InitBasic()
	defer th.TearDown()

	th.App.SetLicense(model.NewTestLicense(""))
	th.App.SetPhase2PermissionsMigrationStatus(true)

	permissionsDefault := []string{
		model.PERMISSION_MANAGE_CHANNEL_ROLES.Id,
		model.PERMISSION_MANAGE_PUBLIC_CHANNEL_MEMBERS.Id,
	}

	// Defer resetting the system scheme permissions
	systemSchemeRoles, err := th.App.GetRolesByNames([]string{
		model.CHANNEL_GUEST_ROLE_ID,
		model.CHANNEL_USER_ROLE_ID,
		model.CHANNEL_ADMIN_ROLE_ID,
	})
	require.Nil(t, err)
	require.Len(t, systemSchemeRoles, 3)

	// defer resetting the system role permissions
	for _, systemRole := range systemSchemeRoles {
		defer th.App.PatchRole(systemRole, &model.RolePatch{
			Permissions: &systemRole.Permissions,
		})
	}

	// Make a channel scheme, clear its permissions
	channelScheme, err := th.App.CreateScheme(&model.Scheme{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Scope:       model.SCHEME_SCOPE_CHANNEL,
	})
	require.Nil(t, err)
	defer th.App.DeleteScheme(channelScheme.Id)

	team := th.CreateTeam()
	defer th.App.PermanentDeleteTeamId(team.Id)

	// Make a channel, set its scheme
	channel := th.CreateChannel(team)
	channel.SchemeId = &channelScheme.Id
	channel, err = th.App.UpdateChannelScheme(channel)
	require.Nil(t, err)

	// Get the truth table from CSV
	file, e := os.Open("tests/channel-role-has-permission.csv")
	require.Nil(t, e)
	defer file.Close()

	b, e := ioutil.ReadAll(file)
	require.Nil(t, e)

	r := csv.NewReader(strings.NewReader(string(b)))
	records, e := r.ReadAll()
	require.Nil(t, e)

	test := func(nonAdminRoleName, nonAdminRoleID, higherScopedAdminRoleName string) {
		for i, row := range records {
			if i == 0 {
				continue
			}
			p, e := strconv.ParseBool(row[0])
			require.Nil(t, e)
			q, e := strconv.ParseBool(row[1])
			require.Nil(t, e)
			r, e := strconv.ParseBool(row[2])
			require.Nil(t, e)
			s, e := strconv.ParseBool(row[3])
			require.Nil(t, e)
			shouldHavePermission, e := strconv.ParseBool(row[4])
			require.Nil(t, e)

			var roleNameUnderTest string
			if s {
				roleNameUnderTest = higherScopedAdminRoleName
			} else {
				roleNameUnderTest = nonAdminRoleName
			}

			// select the permission to test (moderated or non-moderated)
			var permission *model.Permission
			if q {
				permission = model.PERMISSION_CREATE_POST // moderated
			} else {
				permission = model.PERMISSION_READ_CHANNEL // non-moderated
			}

			// add or remove the permission from the higher-scoped scheme
			higherScopedRole, testErr := th.App.GetRoleByName(roleNameUnderTest)
			require.Nil(t, testErr)

			var higherScopedPermissions []string
			if p {
				higherScopedPermissions = []string{permission.Id}
			} else {
				higherScopedPermissions = permissionsDefault
			}
			higherScopedRole, testErr = th.App.PatchRole(higherScopedRole, &model.RolePatch{Permissions: &higherScopedPermissions})
			require.Nil(t, testErr)

			// get channel role
			var channelRoleName string
			if s {
				channelRoleName = channelScheme.DefaultChannelAdminRole
			} else if nonAdminRoleID == model.CHANNEL_GUEST_ROLE_ID {
				channelRoleName = channelScheme.DefaultChannelGuestRole
			} else if nonAdminRoleID == model.CHANNEL_USER_ROLE_ID {
				channelRoleName = channelScheme.DefaultChannelUserRole
			}
			channelRole, testErr := th.App.GetRoleByName(channelRoleName)
			require.Nil(t, testErr)

			// add or remove the permission from the channel scheme
			var channelSchemePermissions []string
			if r {
				channelSchemePermissions = []string{permission.Id}
			} else {
				channelSchemePermissions = permissionsDefault
			}
			channelRole, testErr = th.App.PatchRole(channelRole, &model.RolePatch{Permissions: &channelSchemePermissions})
			require.Nil(t, testErr)

			testCallback(t, th, permissionInheritanceTestData{
				channelRole:          channelRole,
				permission:           permission,
				shouldHavePermission: shouldHavePermission,
				channel:              channel,
				higherScopedRole:     higherScopedRole,
				truthTableRow:        row,
			})
		}
	}

	// test all 24 permutations where the higher-scoped scheme is the system scheme
	test(model.CHANNEL_GUEST_ROLE_ID, model.CHANNEL_GUEST_ROLE_ID, model.CHANNEL_ADMIN_ROLE_ID)
	test(model.CHANNEL_USER_ROLE_ID, model.CHANNEL_USER_ROLE_ID, model.CHANNEL_ADMIN_ROLE_ID)

	// create a team scheme, assign it to the team
	teamScheme, err := th.App.CreateScheme(&model.Scheme{
		Name:        model.NewId(),
		DisplayName: model.NewId(),
		Scope:       model.SCHEME_SCOPE_TEAM,
	})
	require.Nil(t, err)
	defer th.App.DeleteScheme(teamScheme.Id)
	team.SchemeId = &teamScheme.Id
	team, err = th.App.UpdateTeamScheme(team)
	require.Nil(t, err)

	// test all 24 permutations where the higher-scoped scheme is a team scheme
	test(teamScheme.DefaultChannelGuestRole, model.CHANNEL_GUEST_ROLE_ID, teamScheme.DefaultChannelAdminRole)
	test(teamScheme.DefaultChannelUserRole, model.CHANNEL_USER_ROLE_ID, teamScheme.DefaultChannelAdminRole)
}
