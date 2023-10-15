package grant

type GrantType string

const (
	GrantTypeAuthorizationCodeRequest GrantType = "authorization_code"
	GrantTypePassword                 GrantType = "password"
	GrantTypeClientCredentialsRequest GrantType = "client_credentials"
	GrantTypeImplicitUserAgentRequest GrantType = "implicit"
	GrantTypeRefreshToken             GrantType = "refresh_token"
)

type ResponseType string

const (
	ResponseTypeCode  ResponseType = "code"
	ResponseTypeToken ResponseType = "token"
)

type ErrorCode string

const (
	ErrorCodeInvalidRequest          ErrorCode = "invalid_request"
	ErrorCodeUnauthorizedClient      ErrorCode = "unauthorized_client"
	ErrorCodeAccessDenied            ErrorCode = "access_denied"
	ErrorCodeUnsupportedResponseType ErrorCode = "unsupported_response_type"
	ErrorCodeInvalidScope            ErrorCode = "invalid_scope"
	ErrorCodeServerError             ErrorCode = "server_error"
	ErrorCodeTemporarilyUnavailable  ErrorCode = "temporarily_unavailable"
	ErrorCodeEmpty                   ErrorCode = ""
)

type TokenType string

const (
	TokenTypeBearer TokenType = "bearer"
	TokenTypeMAC    TokenType = "mac"
)
