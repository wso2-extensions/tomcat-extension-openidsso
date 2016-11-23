/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.tomcat.oidcsso.extension;

/**
 * This class defines constants used within the unit-tests of tomcat extension for OpenID Connect.
 */
public class TestConstants {
    public static final String TEST_RESOURCES = System.getProperty("test.resources");
    public static final String CATALINA_BASE = "oidcExtension";
    public static final String WEB_APP_BASE = "webapps";
    public static final String SAMPLE_WEB_APP = "sample";
    public static final String FAULTY_SAMPLE_WEB_APP = "faulty-sample";
    public static final String SSL_PROTOCOL = "https";
    public static final int SSL_PORT = 8443;
    public static final String DEFAULT_TOMCAT_HOST = "localhost";

    // test constants for oidc configuration
    public static final String CLIENT_ID = "abdefghijklm_123415";
    public static final String CLIENT_SECRET = "6789nopqrstuvwxyz";
    public static final String REDIRECT_URI = "http://localhost:8080/foo-app/openid";
    public static final String SCOPE = "openid,profile";
    public static final String CLAIMS = "address";
    public static final String RESPONSE_TYPE = "code";
    public static final String GRANT_TYPE = "authorization_code";
    public static final String AUTHENTICATION_ENDPOINT = "https://localhost:9443/oauth2/authorize";
    public static final String TOKEN_ENDPOINT = "https://localhost:9443/oauth2/token";
    public static final String USER_INFO_ENDPOINT = "https://localhost:9443/oauth2/userinfo?schema=openid";
    public static final String LOGOUT_ENDPOINT = "https://localhost:9443/oidc/logout";

    //  test constants for server level security configurations
    public static final String TYPE = "JKS";
    public static final String PRIVATE_KEY_ALIAS = "wso2carbon";
    public static final String TRUSTSTORE_PATH = "${catalina.base}/conf/wso2/client-truststore.jks";
    public static final String TRUSTSTORE_PASSWORD = "wso2carbon";

    // Authentication Response Constants
    public static final String CODE = "8e0e20bb-4e33-3ea6-b931-66eb5a73d9d3";
    public static final String STATE = "hello";
    public static final String REQUEST_SCOPE = "openid,email";
    public static final String SESSION_STATE = "25960f5fd9c7c4c3b4d07c776bc5feb5ac9b8752861057f01.mWZHKZC3k9vc7JnOGCU";
    public static final String ERROR = "invalid_request";

    public static final String AUTHENTICATION_REQUEST = "https://localhost:9443/oauth2/authorize?display=popup&" +
            "response_type=code&client_id=abdefghijklm_123415&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Ffoo-app" +
            "%2Fopenid&scope=openid+email&state=hello&claims=%7B%22userinfo%22%3A%7B%22address%22%3Anull%7D%7D";

    public static final String AUTHENTICATION_RESPONSE_URL = SSL_PROTOCOL + "://" + DEFAULT_TOMCAT_HOST + ":" +
            SSL_PORT + "/" + SAMPLE_WEB_APP + "/openid";
    public static final String AUTHENTICATION_RESPONSE_QUERY = "code=" + CODE + "&state=" + STATE + "&session_state=" +
            SESSION_STATE;
    public static final String AUTHENTICATION_ERROR_RESPONSE_QUERY = "error=" + ERROR + "&state=" + STATE;

    //Http token response constants
    public static final String CACHE_CONTROL = "no-store";
    public static final String CONTENT_TYPE = "application/json";
    public static final String PRAGMA = "no-cache";

    //token request test constants

    public static final String ACCESS_TOKEN = "SlAV32hkKG";
    public static final String REFRESH_TOKEN = "8xLOxBtZp8";
    public static final String TOKEN_TYPE = "Bearer";
    public static final String EXPIRES_IN = "3600";
    public static final String X509_CERTIFICATE_SHA_1_THUMBPRINT =
            "NmJmOGUxMzZlYjM2ZDRhNTZlYTA1YzdhZTRiOWE0NWI2M2JmOTc1ZA";
    public static final String KEY_ID = "d0ec514a32b6f88c0abd12a2840699bdd3deba9d";
    public static final String SUBJECT = "admin";
    public static final String SIGNATURE = "atLaPBLXWzoVckDz8xFe5bdP9hRuv3Xlf05pEpcwezDyMSfjb84ACkvM96qlluJDDE1fjc" +
            "z9tsTU97I5hd_DYd_mAhESlmmC6g_36yC7mm7QOFqiYxoTpnA_a_R8EdIyBiT_tvROQDj6D1F5wuvB7Aeo5n7wq4Wq8nFfxIHuiJ0";

    public static final String ID_TOKEN = "eyJ4NXQiOiJObUptT0dVeE16WmxZak0yWkRSaE5UWmxZVEExWXpkaFpUUmlPV0UwTldJMk0ySm" +
            "1PVGMxWkEiLCJraWQiOiJkMGVjNTE0YTMyYjZmODhjMGFiZDEyYTI4NDA2OTliZGQzZGViYTlkIiwiYWxnIjoiUlMyNTYifQ.eyJhdF" +
            "9oYXNoIjoiQ29BVTlMYjNjQWMtYUo5WThZLTNXQSIsInN1YiI6ImFkbWluIiwiYXVkIjpbImJjY054dk5qZlBrY2FPSWJhSHhaNmN2VU" +
            "ZIZ2EiXSwiYXpwIjoiYmNjTnh2TmpmUGtjYU9JYmFIeFo2Y3ZVRkhnYSIsImF1dGhfdGltZSI6MTQ3OTQ1MTYzMSwiaXNzIjoiaHR0cH" +
            "M6XC9cL2xvY2FsaG9zdDo5NDQzXC9vYXV0aDJcL3Rva2VuIiwiZXhwIjoxNDc5NDU1MjMxLCJpYXQiOjE0Nzk0NTE2MzF9.VIZsSSfZ" +
            "_6hKaOZ7KoRHWtyAaLha9z7hG6VqAvPDbKEX1-Mh866X_Ct7iithuSarkCQN4QHmBkHODczLg4MNPC0FTrjhmeTA9AbGjzNjuBbFdka9" +
            "gR4AqCpNb_JOWD8iHRAGSzMCHdrb8j8oLqRGD7NwkGlQfdPvxKb5ZITscdA";

    public static final String MODULUS = "104389905404607483833617268973978551958403030832611050189027318534771307" +
            "81081472855052920570317205920575160995332044534327484820902067075658372507756364690060460790391002366" +
            "33116138109156530183033065824016060914216220303447956356807733204526137099839921588472094995755372675" +
            "30495679082469928078242466031287097";

    public static final String EXPONENT = "65537";
    public static final String PRIVATE_KEY = "DA909C62B1BDD210C5C70382B15C9AEF0A5B423AA1072DCE3EC172C93FBBD74F";

    public static final String USER_INFO = "{\"sub\":\"248289761001\",\"name\":\"Jane Doe\",\"given_name\":\"Jane\"}";
    public static final String USER_INFO_ERROR = "invalid_token";

    //logout request constants

    public static final String LOGOUT_REQUEST = "https://localhost:9443/oidc/logout?id_token_hint=" + ID_TOKEN;

    /**
     * Prevents instantiating this class.
     */
    private TestConstants() {
    }
}
