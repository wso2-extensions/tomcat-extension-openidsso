package org.wso2.carbon.tomcat.oidcsso.extension;

/**
 * This class defines constants used within the tomcat extension for OpenID Connect.
 */
public class Constants {
    public static final String OPENID = "openid";
    public static final String ERROR_AUTHENTICATION_RESPONSE = "Error Authentication Response";
    public static final String AUTHENTICATION_RESPONSE_VALIDATION_FAILED = "Authentication Response Validation Failed";
    public static final String TOKEN_RESPONSE_VALIDATION_FAILED = "Token Response Validation Failed";
    public static final String ERROR_TOKEN_RESPONSE = "Error Token Response";
    public static final String ERROR_USER_INFO_RESPONSE = "UserInfo Error Response";
    public static final String USER_INFO_RESPONSE = "UserInfo response";
    public static final String SESSION_BEAN = "org.wso2.appserver.webapp.security.oidc.bean.OIDCLoggedInSession";
    public static final String LOGOUT = "logout";
    public static final String TOKEN_TYPE = "token_type";
    public static final String EXPIRES_IN = "expires_in";
    public static final int STATE_LENGTH = 10;
    public static final String STATE = "state";
    public static final String SCOPE = "scope";
    public static final String CUSTOM_PARAMETERS = "custom_parameters";
    public static final Character SEPERATOR = '?';
    public static final String CLIENT_ID = "clientID";
    public static final String SESSION_STATE = "session_state";
    public static final String CLAIMS = "claims";
    public static final String ERROR = "error";
    public static final String CODE = "code";
    public static final String ACCESS_DENIED = "access_denied";
    public static final String LOGIN_REQUIRED = "login_required";
    public static final String SERVER_URL = "http://localhost:8080";
    public static final String SIGN_IN = "signin";
    public static final String RE_AUTHENTICATE = "re-authenticate";
    public static final String KEY_TYPE = "kty";
    public static final String X509_CERTIFICATE_SHA_1_THUMBPRINT = "x5t";
    public static final String X509_CERTIFICATE_SHA_1_THUMBPRINT_VALUE =
            "NmJmOGUxMzZlYjM2ZDRhNTZlYTA1YzdhZTRiOWE0NWI2M2JmOTc1ZA";
    public static final String KEY_ID = "kid";
    public static final String KEY_ID_VALUE = "d0ec514a32b6f88c0abd12a2840699bdd3deba9d";
    public static final String ALGORITHM = "alg";
    public static final String ALGORITHM_TYPE = "RS256";
    public static final String MODULUS = "n";
    public static final String EXPONENT = "e";
    public static final String TOMCAT_CONFIGURATION_DIRECTORY = "conf";
    public static final String OIDC_CONFIGURATION_DIRECTORY = "wso2";
    public static final String WEBAPP_DESCRIPTOR = "oidc-config.xml";
    public static final String WEBAPP_DESCRIPTOR_SCHEMA = "oidc-config.xsd";
    public static final String WEB_CONTAINER_RESOURCE_FOLDER = "META-INF";
    public static final String PROMPT = "prompt";
    public static final String NONE = "none";
    public static final String JAVA_TRUST_STORE_LOCATION = "javax.net.ssl.trustStore";
    public static final String JAVA_TRUST_STORE_PASSWORD = "javax.net.ssl.trustStorePassword";
    public static final String JAVA_TRUST_STORE_TYPE = "javax.net.ssl.trustStoreType";

    /**
     * Prevents instantiating this class.
     */
    private Constants() {
    }
}
