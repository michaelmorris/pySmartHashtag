"""URLs for different services and error code mapping."""

API_KEY = "3_L94eyQ-wvJhWm7Afp1oBhfTGXZArUfSHHW9p9Pncg513hZELXsxCfMWHrF8f5P5a"
SERVER_URL = "https://awsapi.future.smart.com/login-app/api/v1/authorize?uiLocales=de-DE"
CONTEXT_URL = "https://awsapi.future.smart.com/login-app/api/v1/authorize?uiLocales=de-DE&uiLocales=de-DE"
AUTH_URL = f"https://auth.smart.com/oidc/op/v1.0/{API_KEY}/authorize/continue"
LOGIN_URL = "https://auth.smart.com/accounts.login"
API_BASE_URL = "https://api.ecloudeu.com"
API_CARS_URL = "/device-platform/user/vehicle/secure"
API_SESION_URL = "/auth/account/session/secure"
API_SELECT_CAR_URL = "/device-platform/user/session/update"
API_TELEMATICS_URL = "/remote-control/vehicle/telematics/"

API_KEY_VOLVO = "806b566d8d8d447d8d99701d222dca39"
APP_ID_VOLVO = "EX30-HA-Integration"
AUTH_URL_VOLVO = "https://volvoid.eu.volvocars.com/as/authorization.oauth2"
AUTHN_FLOW_URL_VOLVO = "https://volvoid.eu.volvocars.com/pf-ws/authn/flows/"
TOKEN_URL_VOLVO = "https://volvoid.eu.volvocars.com/as/token.oauth2"
API_BASE_URL_VOLVO = "https://api-vlv.ecloudeu.com"

HTTPX_TIMEOUT = 30.0
