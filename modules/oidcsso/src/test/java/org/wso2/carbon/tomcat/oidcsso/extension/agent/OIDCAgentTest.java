/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.tomcat.oidcsso.extension.agent;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import net.minidev.json.JSONObject;
import org.apache.catalina.Context;
import org.apache.catalina.Globals;
import org.apache.catalina.Host;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.connector.Request;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.core.StandardHost;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.tomcat.oidcsso.extension.TestConstants;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.AuthenticationResponse;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.RequestParameters;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.TokenResponse;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.UserInformationResponse;
import org.wso2.carbon.tomcat.oidcsso.extension.oidc.InMemoryStateStore;
import org.wso2.carbon.tomcat.oidcsso.extension.oidc.StateStore;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.OIDCConfiguration;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.OIDCConfigurationLoader;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.AuthenticationRequestException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.AuthenticationResponseException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.LogoutException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.OIDCConfigurationRuntimeException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.TokenException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.UserInfoException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * This class defines unit-tests for OpenID Connect agent class.
 */
public class OIDCAgentTest {
    private static final Path catalina_base = Paths.get(TestConstants.TEST_RESOURCES, TestConstants.CATALINA_BASE);
    private static final Host host = new StandardHost();
    private static final Context sample_context = new StandardContext();

    @BeforeClass
    public void setupCatalinaBaseEnv() throws IOException {
        System.setProperty(Globals.CATALINA_BASE_PROP, catalina_base.toString());
        prepareCatalinaComponents();
        loadWebappConfiguration();
    }

    @Test(description = "Test the generated authentication request", priority = 1)
    public void testBuildAuthenticationRequest() throws AuthenticationRequestException {
        OIDCAgent oidcAgent = new OIDCAgent();
        OIDCConfiguration oidcConfiguration = OIDCConfigurationLoader.getOIDCConfiguration(sample_context).get();
        RequestParameters requestParameters = new RequestParameters();
        requestParameters.setState(TestConstants.STATE);
        requestParameters.setScope(TestConstants.REQUEST_SCOPE);
        Map<String, String> customParameters = new HashMap<>();
        customParameters.put("display", "popup");
        requestParameters.setCustomParameters(customParameters);
        StateStore stateStore = new InMemoryStateStore();
        String authenticationRequest = oidcAgent.buildAuthenticationRequest(oidcConfiguration, requestParameters,
                stateStore);
        Assert.assertTrue(authenticationRequest.trim().equals(TestConstants.AUTHENTICATION_REQUEST));
    }

    @Test(description = "test the authentication request builder method with invalid input values",
            expectedExceptions = AuthenticationRequestException.class, priority = 2)
    public void testInvalidBuildAuthenticationRequest() throws AuthenticationRequestException {
        OIDCConfiguration oidcConfiguration = OIDCConfigurationLoader.getOIDCConfiguration(sample_context).get();
        RequestParameters requestParameters = new RequestParameters();
        OIDCAgent oidcAgent = new OIDCAgent();
        StateStore stateStore = new InMemoryStateStore();
        requestParameters.setScope(TestConstants.INVALID_SCOPE);
        oidcAgent.buildAuthenticationRequest(oidcConfiguration, requestParameters, stateStore);
    }

    @Test(description = "test the received authentication response", priority = 3)
    public void testProcessAuthenticationResponse() throws AuthenticationResponseException {
        OIDCAgent oidcAgent = new OIDCAgent();
        StateStore stateStore = new InMemoryStateStore();
        stateStore.storeState(TestConstants.STATE);

        Request request = mock(Request.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.AUTHENTICATION_RESPONSE_URL));
        when(request.getQueryString()).thenReturn(TestConstants.AUTHENTICATION_RESPONSE_QUERY);

        AuthenticationResponse authenticationResponse = oidcAgent.processAuthenticationResponse(request, stateStore);
        Assert.assertTrue(compareAuthenticationResponse(authenticationResponse, prepareAuthenticationResponse()));
    }

    @Test(description = "test a authentication response with an invalid request URI",
            expectedExceptions = AuthenticationResponseException.class, priority = 4)
    public void testInvalidURIAuthenticationResponse() throws AuthenticationResponseException {
        OIDCAgent oidcAgent = new OIDCAgent();
        StateStore stateStore = new InMemoryStateStore();
        stateStore.storeState(TestConstants.STATE);
        Request request = mock(Request.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://"));
        when(request.getQueryString()).thenReturn(" ");
        oidcAgent.processAuthenticationResponse(request, stateStore);
    }

    @Test(description = "test the process authentication response method with invalid response",
            expectedExceptions = AuthenticationResponseException.class, priority = 5)
    public void testInvalidAuthenticationResponse() throws AuthenticationResponseException {
        OIDCAgent oidcAgent = new OIDCAgent();
        StateStore stateStore = new InMemoryStateStore();
        stateStore.storeState(TestConstants.STATE);
        Request request = mock(Request.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.INVALID_AUTHENTICATION_RESPONSE_URL));
        when(request.getQueryString()).thenReturn(TestConstants.INVALID_AUTHENTICATION_RESPONSE_QUERY);
        oidcAgent.processAuthenticationResponse(request, stateStore);
    }

    @Test(description = "validate authentication response with a empty state store",
            expectedExceptions = AuthenticationResponseException.class, priority = 6)
    public void testValidateAuthenticationResponse() throws AuthenticationResponseException {
        OIDCAgent oidcAgent = new OIDCAgent();
        Request request = mock(Request.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.AUTHENTICATION_RESPONSE_URL));
        when(request.getQueryString()).thenReturn(TestConstants.AUTHENTICATION_RESPONSE_QUERY);
        StateStore stateStore = new InMemoryStateStore();
        stateStore.getStates().clear();
        oidcAgent.processAuthenticationResponse(request, stateStore);
    }

    @Test(description = "test the authentication error response process", priority = 7)
    public void testProcessAuthenticationErrorResponse() throws AuthenticationResponseException {
        OIDCAgent oidcAgent = new OIDCAgent();
        StateStore stateStore = new InMemoryStateStore();
        stateStore.storeState(TestConstants.STATE);
        Request request = mock(Request.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer(TestConstants.AUTHENTICATION_RESPONSE_URL));
        when(request.getQueryString()).thenReturn(TestConstants.AUTHENTICATION_ERROR_RESPONSE_QUERY);
        AuthenticationResponse authenticationResponse = oidcAgent.processAuthenticationResponse(request, stateStore);
        Assert.assertTrue(authenticationResponse.getCode() == null);
    }

    @Test(description = "test the generated token request and received token response", priority = 8)
    public void testProcessTokenResponse() throws IOException, ParseException, TokenException, CertificateException,
            java.text.ParseException, NoSuchAlgorithmException, KeyStoreException, JOSEException, InvalidKeyException,
            UnrecoverableKeyException {
        OIDCAgent oidcAgent = new OIDCAgent();
        OIDCConfiguration oidcConfiguration = OIDCConfigurationLoader.getOIDCConfiguration(sample_context).get();
        String idToken = prepareIDToken();
        HTTPRequest request = mock(HTTPRequest.class);
        HTTPResponse httpResponse = prepareHttpTokenResponse(idToken);
        when(request.send()).thenReturn(httpResponse);
        TokenResponse tokenResponse = oidcAgent.processTokenResponse(request, oidcConfiguration);
        Assert.assertTrue(compareTokenResponses(tokenResponse, prepareTokenResponse(idToken)));
    }

    @Test(description = "test process token response with error response", priority = 9)
    public void testProcessErrorTokenResponse() throws ParseException, IOException, TokenException {
        OIDCAgent oidcAgent = new OIDCAgent();
        OIDCConfiguration oidcConfiguration = OIDCConfigurationLoader.getOIDCConfiguration(sample_context).get();
        HTTPRequest request = mock(HTTPRequest.class);
        HTTPResponse httpResponse = prepareHttpErrorTokenResponse();
        when(request.send()).thenReturn(httpResponse);
        TokenResponse tokenResponse = oidcAgent.processTokenResponse(request, oidcConfiguration);
        Assert.assertTrue(tokenResponse.getAccessToken() == null);
    }

    @Test(description = "test process token response with invalid id token response",
            expectedExceptions = TokenException.class, priority = 10)
    public void testProcessInvalidIDTokenResponse() throws IOException, ParseException, TokenException {
        OIDCAgent oidcAgent = new OIDCAgent();
        OIDCConfiguration oidcConfiguration = OIDCConfigurationLoader.getOIDCConfiguration(sample_context).get();
        HTTPRequest request = mock(HTTPRequest.class);
        when(request.send()).thenReturn(prepareHttpInvalidIDTokenResponse());
        oidcAgent.processTokenResponse(request, oidcConfiguration);
    }

    @Test(description = "test process token response with invalid content", expectedExceptions = TokenException.class,
            priority = 11)
    public void testProcessInvalidContentTokenResponse() throws IOException, TokenException, ParseException {
        OIDCAgent oidcAgent = new OIDCAgent();
        OIDCConfiguration oidcConfiguration = OIDCConfigurationLoader.getOIDCConfiguration(sample_context).get();
        HTTPRequest request = mock(HTTPRequest.class);
        when(request.send()).thenReturn(prepareHttpInvalidContentTokenResponse());
        oidcAgent.processTokenResponse(request, oidcConfiguration);
    }

    @Test(description = "test process token response with invalid token response",
            expectedExceptions = TokenException.class, priority = 12)
    public void testProcessInvalidTokenresponse() throws IOException, ParseException, TokenException,
            CertificateException, java.text.ParseException, NoSuchAlgorithmException, KeyStoreException,
            JOSEException, UnrecoverableKeyException, InvalidKeyException {
        OIDCAgent oidcAgent = new OIDCAgent();
        OIDCConfiguration oidcConfiguration = OIDCConfigurationLoader.getOIDCConfiguration(sample_context).get();
        HTTPRequest request = mock(HTTPRequest.class);
        when(request.send()).thenReturn(prepareHttpInvalidTokenResponse());
        oidcAgent.processTokenResponse(request, oidcConfiguration);
    }

    @Test(description = "test with invalid key store", expectedExceptions = TokenException.class, priority = 13)
    public void testInvalidKeyStore() throws CertificateException, java.text.ParseException, NoSuchAlgorithmException,
            IOException, JOSEException, KeyStoreException, UnrecoverableKeyException, InvalidKeyException,
            ParseException, TokenException {
        OIDCAgent oidcAgent = new OIDCAgent();
        OIDCConfiguration oidcConfiguration = OIDCConfigurationLoader.getOIDCConfiguration(sample_context).get();
        oidcConfiguration.getTruststore().setLocation("hnkjdsvnkjdhvnkjn");
        String idToken = prepareIDToken();
        HTTPRequest request = mock(HTTPRequest.class);
        HTTPResponse httpResponse = prepareHttpTokenResponse(idToken);
        when(request.send()).thenReturn(httpResponse);
        oidcAgent.processTokenResponse(request, oidcConfiguration);
    }

    @Test(description = "test successful user info response", priority = 14)
    public void testGetUserInfoResponse() throws ParseException, IOException, UserInfoException {
        OIDCAgent oidcAgent = new OIDCAgent();
        HTTPRequest request = mock(HTTPRequest.class);
        when(request.send()).thenReturn(prepareHttpSuccessfulUserInfoResponse());
        UserInformationResponse userInformationResponse = oidcAgent.processUserInfoResponse(request);
        Assert.assertTrue(userInformationResponse.getUserInfo().trim().equals(TestConstants.USER_INFO));
    }

    @Test(description = "test user info error response", priority = 15)
    public void testGetUserInfoErrorResponse() throws IOException, UserInfoException {
        OIDCAgent oidcAgent = new OIDCAgent();
        HTTPRequest request = mock(HTTPRequest.class);
        when(request.send()).thenReturn(prepareHttpErrorUserInfoResponse());
        UserInformationResponse userInformationResponse = oidcAgent.processUserInfoResponse(request);
        Assert.assertTrue(userInformationResponse.getUserInfo() == null);
    }

    @Test(description = "test with invalid user info response", expectedExceptions = UserInfoException.class,
            priority = 16)
    public void testGetUserInfoInvalidResponse() throws IOException, UserInfoException, ParseException {
        OIDCAgent oidcAgent = new OIDCAgent();
        HTTPRequest request = mock(HTTPRequest.class);
        when(request.send()).thenReturn(prepareInvalidUserInfoResponse());
        oidcAgent.processUserInfoResponse(request);
    }

    @Test(description = "test the generated logout request", priority = 17)
    public void testBuildLogoutRequest() throws LogoutException {
        OIDCAgent oidcAgent = new OIDCAgent();
        OIDCConfiguration oidcConfiguration = OIDCConfigurationLoader.getOIDCConfiguration(sample_context).get();
        String logoutRequest = oidcAgent.buildLogoutRequest(oidcConfiguration, TestConstants.ID_TOKEN);
        Assert.assertTrue(logoutRequest.trim().equals(TestConstants.LOGOUT_REQUEST));
    }

    @Test(description = "test logout request builder method with invalid ID Token",
            expectedExceptions = LogoutException.class, priority = 18)
    public void testInvalidIDTokenBuildLogoutRequest() throws LogoutException {
        OIDCAgent oidcAgent = new OIDCAgent();
        OIDCConfiguration oidcConfiguration = OIDCConfigurationLoader.getOIDCConfiguration(sample_context).get();
        oidcAgent.buildLogoutRequest(oidcConfiguration, TestConstants.SAMPLE_STRING);
    }

    private static void prepareCatalinaComponents() {
        host.setAppBase(TestConstants.WEB_APP_BASE);
        sample_context.setParent(host);
        sample_context.setDocBase(TestConstants.SAMPLE_WEB_APP);
    }

    private static void loadWebappConfiguration() throws OIDCConfigurationRuntimeException {
        OIDCConfigurationLoader oidcConfigurationLoader = new OIDCConfigurationLoader();
        List<Lifecycle> components = new ArrayList<>();
        components.add(host);
        components.add(sample_context);
        components
                .stream()
                .forEach(component -> oidcConfigurationLoader.
                        lifecycleEvent(new LifecycleEvent(component, Lifecycle.BEFORE_START_EVENT, null)));
    }

    private static AuthenticationResponse prepareAuthenticationResponse() {
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setCode(TestConstants.CODE);
        authenticationResponse.setSessionState(TestConstants.SESSION_STATE);
        return authenticationResponse;
    }

    private static HTTPResponse prepareHttpTokenResponse(String idToken) throws ParseException, CertificateException,
            java.text.ParseException, NoSuchAlgorithmException, IOException, JOSEException, KeyStoreException,
            InvalidKeyException {
        HTTPResponse response = new HTTPResponse(HTTPResponse.SC_OK);
        response.setCacheControl(TestConstants.CACHE_CONTROL);
        response.setContentType(TestConstants.CONTENT_TYPE);
        response.setPragma(TestConstants.PRAGMA);
        Map<String, String> contentMap = new HashMap<>();
        contentMap.put("access_token", TestConstants.ACCESS_TOKEN);
        contentMap.put("token_type", TestConstants.TOKEN_TYPE);
        contentMap.put("refresh_token", TestConstants.REFRESH_TOKEN);
        contentMap.put("expires_in", TestConstants.EXPIRES_IN);
        contentMap.put("id_token", idToken);
        response.setContent(new JSONObject(contentMap).toJSONString());
        return response;
    }

    private static HTTPResponse prepareHttpErrorTokenResponse() throws ParseException {
        HTTPResponse response = new HTTPResponse(HTTPResponse.SC_BAD_REQUEST);
        response.setCacheControl(TestConstants.CACHE_CONTROL);
        response.setContentType(TestConstants.CONTENT_TYPE);
        response.setPragma(TestConstants.PRAGMA);
        Map<String, String> contentMap = new HashMap<>();
        contentMap.put("error", TestConstants.ERROR);
        response.setContent(new JSONObject(contentMap).toJSONString());
        return response;
    }

    private static HTTPResponse prepareHttpInvalidIDTokenResponse() throws ParseException {
        HTTPResponse response = new HTTPResponse(HTTPResponse.SC_OK);
        response.setCacheControl(TestConstants.CACHE_CONTROL);
        response.setContentType(TestConstants.CONTENT_TYPE);
        response.setPragma(TestConstants.PRAGMA);
        Map<String, String> contentMap = new HashMap<>();
        contentMap.put("access_token", TestConstants.ACCESS_TOKEN);
        contentMap.put("token_type", TestConstants.TOKEN_TYPE);
        contentMap.put("refresh_token", TestConstants.REFRESH_TOKEN);
        contentMap.put("expires_in", TestConstants.EXPIRES_IN);
        contentMap.put("id_token", TestConstants.ID_TOKEN);
        response.setContent(new JSONObject(contentMap).toJSONString());
        return response;
    }

    private static HTTPResponse prepareHttpInvalidContentTokenResponse() throws ParseException {
        HTTPResponse response = new HTTPResponse(HTTPResponse.SC_OK);
        response.setCacheControl(TestConstants.CACHE_CONTROL);
        response.setContentType(TestConstants.CONTENT_TYPE);
        response.setPragma(TestConstants.PRAGMA);
        response.setContent("sdkjvndsvkldsjvlkdsmvls");
        return response;
    }

    private static HTTPResponse prepareHttpInvalidTokenResponse()
            throws CertificateException, java.text.ParseException, NoSuchAlgorithmException, IOException, JOSEException,
            KeyStoreException, UnrecoverableKeyException, InvalidKeyException, ParseException {
        HTTPResponse response = new HTTPResponse(HTTPResponse.SC_OK);
        response.setCacheControl(TestConstants.CACHE_CONTROL);
        response.setContentType(TestConstants.CONTENT_TYPE);
        response.setPragma(TestConstants.PRAGMA);
        Map<String, String> contentMap = new HashMap<>();
        contentMap.put("token_type", TestConstants.TOKEN_TYPE);
        contentMap.put("refresh_token", TestConstants.REFRESH_TOKEN);
        contentMap.put("expires_in", TestConstants.EXPIRES_IN);
        contentMap.put("id_token", prepareIDToken());
        response.setContent(new JSONObject(contentMap).toJSONString());
        return response;
    }

    private static TokenResponse prepareTokenResponse(String idToken) {
        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setAccessToken(TestConstants.ACCESS_TOKEN);
        tokenResponse.setIdToken(idToken);
        tokenResponse.setExpiresIn(TestConstants.EXPIRES_IN);
        tokenResponse.setRefreshToken(TestConstants.REFRESH_TOKEN);
        tokenResponse.setTokenType(TestConstants.TOKEN_TYPE);
        return tokenResponse;
    }

    private static String prepareIDToken() throws java.text.ParseException, IOException, KeyStoreException,
            CertificateException, NoSuchAlgorithmException, InvalidKeyException, JOSEException,
            UnrecoverableKeyException {
        OIDCConfiguration oidcConfiguration = OIDCConfigurationLoader.getOIDCConfiguration(sample_context).get();
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.RS256);
        header.x509CertThumbprint(new Base64URL(TestConstants.X509_CERTIFICATE_SHA_1_THUMBPRINT));
        header.keyID(TestConstants.KEY_ID);
        JWTClaimsSet.Builder claimSet = new JWTClaimsSet.Builder();
        claimSet.subject(TestConstants.SUBJECT);
        claimSet.audience(oidcConfiguration.getClientID());
        claimSet.issuer(String.valueOf(oidcConfiguration.getTokenEndpoint()));
        Date date = new Date();
        claimSet.issueTime(date);
        claimSet.expirationTime(new Date(date.getTime() + 3600000));
        OIDCConfiguration.TrustStore truststore = oidcConfiguration.getTruststore();
        String filePath = (new File(TestConstants.KEYSTORE_PATH)).getAbsolutePath();
        InputStream file = new FileInputStream(filePath);
        KeyStore keyStore = KeyStore.getInstance(truststore.getType());
        keyStore.load(file, truststore.getPassword().toCharArray());
        Key privateKey = keyStore.getKey(truststore.getKeyAlias(), truststore.getPassword().toCharArray());

        JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
        SignedJWT signedJWT = new SignedJWT(header.build(), claimSet.build());
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private static HTTPResponse prepareHttpSuccessfulUserInfoResponse() throws ParseException {
        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
        httpResponse.setContentType(TestConstants.CONTENT_TYPE);
        Map<String, String> contentMap = new HashMap<>();
        contentMap.put("sub", "248289761001");
        contentMap.put("name", "Jane Doe");
        contentMap.put("given_name", "Jane");
        httpResponse.setContent(new JSONObject(contentMap).toJSONString());
        return httpResponse;
    }

    private static HTTPResponse prepareHttpErrorUserInfoResponse() {
        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_UNAUTHORIZED);
        httpResponse.setWWWAuthenticate("Bearer realm=\"example.com\", error=\"invalid_token\"");
        return httpResponse;
    }

    private static HTTPResponse prepareInvalidUserInfoResponse() throws ParseException {
        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
        httpResponse.setContentType(TestConstants.CONTENT_TYPE);
        httpResponse.setContent(TestConstants.SAMPLE_STRING);
        return httpResponse;
    }

    private static boolean compareAuthenticationResponse(AuthenticationResponse actual,
                                                         AuthenticationResponse expected) {
        if ((actual != null) && (expected != null)) {
            boolean code = actual.getCode().trim().equals(expected.getCode());
            boolean sessionState = actual.getSessionState().trim().equals(expected.getSessionState());
            return (code && sessionState);
        } else {
            return ((actual == null) && (expected == null));
        }
    }

    private static boolean compareTokenResponses(TokenResponse actual, TokenResponse expected) {
        if ((actual != null) && (expected != null)) {
            boolean accessToken = actual.getAccessToken().trim().equals(expected.getAccessToken());
            boolean idToken = actual.getIdToken().trim().equals(expected.getIdToken());
            boolean tokenType = actual.getTokenType().trim().equals(expected.getTokenType());
            boolean refreshToken = actual.getRefreshToken().trim().equals(expected.getRefreshToken());
            boolean expiresIn = actual.getExpiresIn().trim().equals(expected.getExpiresIn());
            return (accessToken && idToken && tokenType && refreshToken && expiresIn);
        } else {
            return ((actual == null) && (expected == null));
        }
    }
}
