package api

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.lumeweb.com/portal-plugin-dashboard/internal"
	"go.lumeweb.com/portal-plugin-dashboard/internal/provider"
	"go.lumeweb.com/portal/core"
	coreTesting "go.lumeweb.com/portal/core/testing"
	"go.lumeweb.com/portal/db/models"
	"gorm.io/gorm"
)

const testAdminEmail = "admin@example.com"

// A new email/password or social registration (no key identity linked) must
// notify the configured admin using the user's real email.
func TestAdminNotify_EmailOrSocialRegistration(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api := core.GetAPI(internal.PLUGIN_NAME).(*API)
		userSvc := coreTesting.GetMockUserService(ctx)
		mailer := coreTesting.GetMockMailerService(ctx)

		user := &models.User{Model: gorm.Model{ID: 42}, Email: "person@example.com"}

		// No key identity => email/social branch, real email in the message.
		userSvc.EXPECT().ListKeyIdentities(mock.Anything, uint(42), mock.Anything, mock.Anything, mock.Anything).
			Return([]*models.KeyIdentity{}, int64(0), nil).Once()

		mailer.EXPECT().TemplateSend(
			adminNewUserMailTemplate,
			mock.Anything,
			mock.MatchedBy(func(v core.MailerTemplateData) bool {
				return v["Email"] == "person@example.com"
			}),
			testAdminEmail,
		).Return(nil).Once()

		api.notifyAdminNewUser(context.Background(), user)

		userSvc.AssertExpectations(tb)
		mailer.AssertExpectations(tb)
	}, coreTesting.WithConfig("core.mail.admin_email", testAdminEmail))
}

// A wallet registration must resolve the wallet address from the key identity
// linked to the created user (never from the synthetic anonymous email) and
// include it in the admin message.
func TestAdminNotify_WalletRegistrationIncludesAddress(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api := core.GetAPI(internal.PLUGIN_NAME).(*API)
		userSvc := coreTesting.GetMockUserService(ctx)
		mailer := coreTesting.GetMockMailerService(ctx)

		// The created user's email is the opaque synthetic anon email; the
		// wallet address must be derived from the linked key identity instead.
		user := &models.User{Model: gorm.Model{ID: 7}, Email: "anon_0xabc123@local.invalid"}

		userSvc.EXPECT().ListKeyIdentities(mock.Anything, uint(7), mock.Anything, mock.Anything, mock.Anything).
			Return([]*models.KeyIdentity{
				{Model: gorm.Model{ID: 1}, Key: "0xabc123", Type: "ethereum"},
			}, int64(1), nil).Once()

		mailer.EXPECT().TemplateSend(
			adminNewUserMailTemplate,
			mock.Anything,
			mock.MatchedBy(func(v core.MailerTemplateData) bool {
				return v["WalletAddress"] == "0xabc123" && v["KeyType"] == "ethereum" &&
					// Must NOT surface the synthetic anon email.
					v["Email"] == nil
			}),
			testAdminEmail,
		).Return(nil).Once()

		api.notifyAdminNewUser(context.Background(), user)

		userSvc.AssertExpectations(tb)
		mailer.AssertExpectations(tb)
	}, coreTesting.WithConfig("core.mail.admin_email", testAdminEmail))
}

// If the key identity lookup fails we cannot tell whether this is a wallet
// registration, so the notification is skipped: the (potentially synthetic
// anonymous) user email must never be exposed to the admin.
func TestAdminNotify_KeyIdentityLookupErrorSkips(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api := core.GetAPI(internal.PLUGIN_NAME).(*API)
		userSvc := coreTesting.GetMockUserService(ctx)
		mailer := coreTesting.GetMockMailerService(ctx)

		// Created user whose email would be the synthetic anon value if leaked.
		user := &models.User{Model: gorm.Model{ID: 7}, Email: "anon_0xabc123@local.invalid"}

		userSvc.EXPECT().ListKeyIdentities(mock.Anything, uint(7), mock.Anything, mock.Anything, mock.Anything).
			Return(nil, int64(0), errors.New("lookup failed")).Once()

		api.notifyAdminNewUser(context.Background(), user)

		// Failure must not send any email (no fallback to the anon email).
		mailer.AssertNotCalled(tb, "TemplateSend")

		userSvc.AssertExpectations(tb)
		mailer.AssertExpectations(tb)
	}, coreTesting.WithConfig("core.mail.admin_email", testAdminEmail))
}

// With no admin email configured the notification is a no-op: no key identity
// lookup occurs and no email is sent.
func TestAdminNotify_UnsetAdminEmailSkips(t *testing.T) {
	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api := core.GetAPI(internal.PLUGIN_NAME).(*API)
		userSvc := coreTesting.GetMockUserService(ctx)
		mailer := coreTesting.GetMockMailerService(ctx)

		api.notifyAdminNewUser(context.Background(),
			&models.User{Model: gorm.Model{ID: 1}, Email: "x@example.com"})

		userSvc.AssertNotCalled(tb, "ListKeyIdentities")
		mailer.AssertNotCalled(tb, "TemplateSend")
	})
}

// A brand-new social account (Created=true) must notify the admin with the
// provider-verified email; linking an identity to an existing account
// (Created=false) must not trigger a (second) notification.
func TestFinishSocialLogin_NewRegistrationNotifiesAdmin(t *testing.T) {
	opts := coreTesting.CombineOptions(
		coreTesting.WithConfig("core.mail.admin_email", testAdminEmail),
		socialTestOptions,
	)

	coreTesting.RunTestCase(t, func(tb coreTesting.TB, ctx coreTesting.TestContext) {
		api, socialSvc := socialTestAPI(ctx)
		userSvc := coreTesting.GetMockUserService(ctx)
		authSvc := core.GetService[*coreTesting.MockAuthService](ctx, core.AUTH_SERVICE)
		mailer := coreTesting.GetMockMailerService(ctx)

		mockUser := &models.User{Model: gorm.Model{ID: 11}, Email: "newsocial@example.com"}
		socialSvc.EXPECT().LoginOrLink(mock.Anything, "google", "uid-11", "newsocial@example.com", true).
			Return(&core.SocialAuthResult{User: mockUser, Created: true, Linked: true, EmailVerified: true}, nil).Once()
		loginToken := CreateTestLoginToken(tb, ctx, "11")
		authSvc.EXPECT().LoginID(mock.Anything, uint(11), mock.Anything, false).Return(loginToken, nil).Once()

		// No key identity => email/social branch.
		userSvc.EXPECT().ListKeyIdentities(mock.Anything, uint(11), mock.Anything, mock.Anything, mock.Anything).
			Return([]*models.KeyIdentity{}, int64(0), nil).Once()

		mailer.EXPECT().TemplateSend(
			adminNewUserMailTemplate,
			mock.Anything,
			mock.MatchedBy(func(v core.MailerTemplateData) bool {
				return v["Email"] == "newsocial@example.com"
			}),
			testAdminEmail,
		).Return(nil).Once()

		reqCtx, w := newSocialTestContext(t)
		err := api.finishSocialLogin(reqCtx, "google",
			&provider.OAuth2User{ProviderUserID: "uid-11", Email: "newsocial@example.com", EmailVerified: true}, "/")
		require.NoError(tb, err)
		require.Equal(tb, http.StatusFound, w.Code)

		mailer.AssertExpectations(tb)
	}, opts)
}
