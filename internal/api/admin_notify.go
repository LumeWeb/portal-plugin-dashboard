package api

import (
	"context"
	"strings"

	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/db/models"
	"go.lumeweb.com/queryutil"
	"go.uber.org/zap"
)

// adminNewUserMailTemplate is the embedded mail template (name derived from
// templates/admin_new_user_{subject,body}.tpl) used to notify the configured
// portal admin about a new user registration.
const adminNewUserMailTemplate = "admin_new_user"

// notifyAdminNewUser emails the configured portal admin (core.mail.admin_email)
// about a newly registered user. It is a no-op when no admin email is
// configured or when the mailer service is unavailable.
//
// Wallet registrations are NOT identified by their synthetic anonymous email.
// Instead the key identities linked to the created user are queried: if any key
// identity exists the registration is treated as a wallet registration and the
// wallet address is included in the message; otherwise the user's real email is
// used (email/password and social registrations).
//
// Callers invoke this only from the dashboard's registration flows after the
// account (and, for wallets, the linked key identity) has been created, so
// unrelated account creations are never notified.
func (a *API) notifyAdminNewUser(ctx context.Context, user *models.User) {
	adminEmail := a.adminEmail()
	if adminEmail == "" {
		return
	}

	mailerSvc := core.GetServiceOptional[core.MailerService](a.Context(), core.MAILER_SERVICE)
	if mailerSvc == nil {
		a.Logger().Warn("mailer service unavailable; skipping admin new-user notification")
		return
	}

	portalName := a.Config().Config().Core.PortalName
	subjectVars := core.MailerTemplateData{"PortalName": portalName}
	bodyVars := core.MailerTemplateData{"PortalName": portalName}

	if user != nil {
		// Determine whether this is a wallet registration by querying the key
		// identities linked to the created user. The first linked key is used
		// as the wallet address in the message. A failed lookup is logged and
		// the notification is skipped entirely: we cannot distinguish a wallet
		// registration from an email/social one, and falling through to the
		// user's (synthetic anonymous) email would leak it to the admin.
		identities, _, err := a.user.ListKeyIdentities(ctx, user.ID, nil, nil, queryutil.DefaultPagination)
		if err != nil {
			a.Logger().Warn("failed to list key identities for admin new-user notification; skipping",
				zap.Error(err),
				zap.Uint("user_id", user.ID),
			)
			return
		}

		if len(identities) > 0 {
			bodyVars["WalletAddress"] = identities[0].Key
			bodyVars["KeyType"] = identities[0].Type
		} else {
			bodyVars["Email"] = user.Email
			bodyVars["FirstName"] = user.FirstName
			bodyVars["LastName"] = user.LastName
		}
	}

	if err := mailerSvc.TemplateSend(adminNewUserMailTemplate, subjectVars, bodyVars, adminEmail); err != nil {
		a.Logger().Error("failed to send admin new-user notification",
			zap.Error(err),
			zap.String("admin_email", adminEmail),
		)
	}
}

// adminEmail returns the configured admin notification address
// (core.mail.admin_email), trimmed, or "" when unset.
func (a *API) adminEmail() string {
	return strings.TrimSpace(a.Config().Config().Core.Mail.AdminEmail)
}
