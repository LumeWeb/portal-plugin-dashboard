# @lumeweb/portal-plugin-dashboard

## 0.3.0 (2026-05-26)

### Breaking Changes

- Replaced Gorilla Mux with Echo framework, potentially requiring updates to existing middleware and route configurations.

This commit introduces a major architectural overhaul of the API, modernizing its structure, dependencies, and overall design. Key changes include:

Core Framework:
- Replaced Gorilla Mux with Echo framework for improved performance and middleware support
- Implemented layered architecture with clear separation of concerns
- Introduced DTO (Data Transfer Object) pattern for request/response payloads, enabling structured data handling and validation
- Implemented dependency injection for services, enhancing testability and modularity

API Improvements:
- Implemented comprehensive input validation using Zog schema validation
- Standardized error handling and HTTP status code responses
- Improved authentication middleware with JWT support
- Enhanced social authentication flow with proper session management
- Restructured API routes with improved organization

### Features

- add avatar upload and retrieval functionality
- add profile update endpoint
- implement remember me functionality for normal, and OTP auth
- implement auto-login after email verification & update default theme
- add operation filters endpoint
- add display name fields to OperationListItem and OperationDetailResponse
- add description field to OperationFilterItem
- improve API key authentication with better token handling

### Fixes

- wrong plugin db import
- use plugin's own migrations instead of core
- correct foreign key syntax in api_keys migrations
- update API key response type in swagger schema
- apply auth middleware to /api/auth/complete
- add cors config to /api/auth/complete
- update plugin config access usage
- migrate sql migrations to goose syntax
- zog passes test values as pointers, so we must use reflection
- we need to depend on the core plugin now
- ensure subdomain event fires after boot complete
- handle existing account errors in email verification
- remove hardcoded https protocol from avatar URL format constant
- Correct context parameter in buildAuthCompleteURL call
- use config.Secure instead of request scheme for HTTPS detection
- missing imports
- unused import
- disable filter parameters from operation schema due to panic issue
- add missing /api/auth/login route
- add missing /api/auth/register route
- correct string pointer handling in operation display infot>
- remove unused import
- replace ctx.Request().RemoteAddr with ctx.RealIP() for better IP detection
- move API_KEY_SERVICE constant to core package
- improve API key validation logic and add error metrics
- remove redundant error check in ValidateAPIKey
- add concrete DTOs for swagger documentation to fix generic type detection
- add filtering and sorting to API keys list endpoint
- use custom stringUUIDSchema for keyID path parameter
- remove unused auth import
- add missing auth import
- remove default 200 response from OTP validate endpoint
- pass mockUser to RegisterLoginTokenWithUser
- map operation filter/sort fields to DB columns before querying
- propagate CID decode errors from operation filter mapping

## 0.2.4

### Patch Changes

- 3f9310e: add build information support

## 0.2.3

### Patch Changes

- 592aa4b: update webapp

## 0.2.2

### Patch Changes

- e8a6284: update webapp

## 0.2.1

### Patch Changes

- d8a18cb: Need to cheat on the go.lumeweb.com/web/go/portal-dashboard version due to go vanity funkiness

## 0.2.0

### Minor Changes

- 447c3fe: ## Features

  - Social login functionality
  - API keys support
  - Account deletion endpoint
  - Live local folder app serving
  - Theme support

  ## Auth & Security

  - 302 redirect login flow
  - OTP flow implementation
  - OTP status in account info
  - Password reset improvements
  - Email verification enhancements
  - Access control optimizations

  ## Refactoring

  - Updated context getters usage
  - Removed custom middleware
  - Updated API usages
  - Package rename to dashboard
  - Plugin restructuring
  - CORS handling improvements
  - Route optimization

  ## Fixes

  - JSON tag issues
  - ResetPassword argument order
  - Password reset OPTIONS support
  - Configuration tag names

  ## CI/CD

  - Node modules cleanup
  - Dependabot setup
  - Core upgrade to 0.2.0
  - Sessions upgrade to 1.4.0
  - Datatypes upgrade to 1.2.4

## 0.1.1

### Patch Changes

- a60f183: This patch includes several improvements and maintenance updates:

  - Documentation updates, including license and changelog files
  - Event handling enhancements, particularly for subdomains
  - Code refactoring for CORS handling and mailer templates
  - Multiple dashboard component updates
  - Various chores and minor improvements

## 0.1.0

### Minor Changes

- 4a64dc3: Initial version split from core
