A new user has just registered on {{.PortalName}}.

{{if .WalletAddress}}Wallet address: {{.WalletAddress}}
Key type: {{.KeyType}}{{else}}Email: {{.Email}}{{if .FirstName}}
Name: {{.FirstName}} {{.LastName}}{{end}}{{end}}

Best regards,
The {{.PortalName}} Team
