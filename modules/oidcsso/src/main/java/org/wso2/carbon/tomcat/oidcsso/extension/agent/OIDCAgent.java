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
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.LogoutRequest;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

import net.minidev.json.JSONObject;

import org.wso2.carbon.tomcat.oidcsso.extension.Constants;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.AuthenticationResponse;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.RequestParameters;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.TokenResponse;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.UserInformationResponse;
import org.wso2.carbon.tomcat.oidcsso.extension.oidc.StateStore;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.OIDCConfiguration;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.AuthenticationRequestException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.AuthenticationResponseException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.LogoutException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.TokenException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.UserInfoException;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;

/**
 * This class defines the API methods to complete OpenID Connect based SSO and SLO.
 */
public class OIDCAgent {

    /**
     * This method builds the OpenID Connect Authentication Request.
     *
     * @param oidcConfiguration Configurations specific to web application.
     * @param requestParameters Parameters defined in the request to be added to the authentication request by the user.
     * @param stateStore        Storage of state values {@link StateStore}.
     * @return Authentication Request String.
     * @throws AuthenticationRequestException If any error occurs during building the request.
     */
    public String buildAuthenticationRequest(OIDCConfiguration oidcConfiguration, RequestParameters requestParameters,
                                             StateStore stateStore) throws AuthenticationRequestException {

        AuthenticationRequestBuilder authenticationRequest = new AuthenticationRequestBuilder();
        authenticationRequest.setAuthenticationEndpoint(oidcConfiguration.getAuthenticationEndpoint());
        authenticationRequest.setClientID(oidcConfiguration.getClientID());
        authenticationRequest.setRedirectURI(oidcConfiguration.getRedirectURI());
        authenticationRequest.setResponseType(oidcConfiguration.getResponseType());
        authenticationRequest.setClaims(Optional.ofNullable(requestParameters.getClaims())
                .orElse(oidcConfiguration.getClaims()));
        authenticationRequest.setScope(Optional.ofNullable(requestParameters.getScope())
                .orElse(oidcConfiguration.getScope()));
        if (requestParameters.getState() != null) {
            authenticationRequest.setState(requestParameters.getState());
        }

        if (requestParameters.getCustomParameters() != null) {
            authenticationRequest.setCustomParameters(requestParameters.getCustomParameters());
        }

        String authenticationRequestString;
        try {
            authenticationRequestString = authenticationRequest.build(stateStore);
        } catch (AuthenticationRequestException e) {
            throw new AuthenticationRequestException("Error occured while building the authentication response.", e);
        }

        return authenticationRequestString;
    }

    /**
     * This method processes the Authentication Response received from the authentication endpoint of the
     * Authorization Server.
     *
     * @param request    HttpServletRequest which is sent from the authentication endpoint.
     * @param stateStore Storage for state values.
     * @return The {@link AuthenticationResponse} object with received values.
     * @throws AuthenticationResponseException If an error occurs during the process.
     */
    public AuthenticationResponse processAuthenticationResponse(HttpServletRequest request, StateStore stateStore)
            throws AuthenticationResponseException {
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        String authresponse = request.getRequestURL().append(Constants.SEPERATOR).append(request.getQueryString())
                .toString();
        URI authenticationResponseURI;
        try {
            authenticationResponseURI = new URI(authresponse);
        } catch (URISyntaxException e) {
            throw new AuthenticationResponseException("Received authentication response is not a valid URI.", e);
        }

        com.nimbusds.openid.connect.sdk.AuthenticationResponse authResp;
        try {
            authResp = AuthenticationResponseParser.parse(authenticationResponseURI);
        } catch (ParseException e) {
            throw new AuthenticationResponseException("Received authentication response is not valid.", e);
        }

        if (authResp instanceof AuthenticationErrorResponse) {
            return authenticationResponse;
        }

        AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResp;
        try {
            authenticationResponse = validateAuthenticationResponse(authenticationResponse, successResponse,
                    stateStore);
        } catch (AuthenticationResponseException e) {
            throw new AuthenticationResponseException("Error occured while validating the authentication response.", e);
        }

        return authenticationResponse;
    }

    /**
     * This method validates the Authentication Response using the state value in the request and response.
     *
     * @param authenticationResponse {@link AuthenticationResponse} to set the values from authentication response if
     *                               the validation is successful.
     * @param successResponse        {@link AuthenticationSuccessResponse} to be validated.
     * @param stateStore             Storage of the state values used in the authentication request
     * @return The {@link AuthenticationResponse} object with received values.
     * @throws AuthenticationResponseException If an error occur during the validation.
     */
    private AuthenticationResponse validateAuthenticationResponse(AuthenticationResponse authenticationResponse,
                                                                  AuthenticationSuccessResponse successResponse,
                                                                  StateStore stateStore)
            throws AuthenticationResponseException {
        if (stateStore.getStates().contains(successResponse.getState().toString())) {
            stateStore.getStates().remove(successResponse.getState().toString());
            authenticationResponse.setCode(successResponse.getAuthorizationCode().toString());
            authenticationResponse.setSessionState(successResponse.getSessionState().toString());
            return authenticationResponse;
        } else {
            throw new AuthenticationResponseException("State store does not has the state value in the response.");
        }
    }

    /**
     * This method generates Token Request, makes a direct call to Token Endpoint in Authorization Server,
     * receives the token response and process it.
     *
     * @param oidcConfiguration Configurations specific to web application.
     * @param code              Authorization code which is received in authentication response.
     * @return {@link TokenResponse} object with received token response values.
     * @throws TokenException If an error occurs during getting the token response.
     */
    public TokenResponse getTokenResponse(OIDCConfiguration oidcConfiguration, String code) throws TokenException {
        AuthorizationCode authorizationCode = new AuthorizationCode(code);
        URI redirectURI = oidcConfiguration.getRedirectURI();
        ClientID clientID = new ClientID(oidcConfiguration.getClientID());
        Secret clientSecret = new Secret(oidcConfiguration.getClientSecret());
        URI tokenEndpoint = oidcConfiguration.getTokenEndpoint();
        ClientAuthentication clientAuthentication = new ClientSecretBasic(clientID, clientSecret);
        AuthorizationGrant authorizationGrant = new AuthorizationCodeGrant(authorizationCode, redirectURI);
        TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuthentication, authorizationGrant);
        HTTPRequest request = tokenRequest.toHTTPRequest();
        return processTokenResponse(request, oidcConfiguration);
    }

    /**
     * This is a default method which sends the token request and processes the received response which is called
     * by the {@code getTokenResponse}.
     *
     * @param request           Generated token request.
     * @param oidcConfiguration Configurations specific to web application.
     * @return {@link TokenResponse} object with received token response values.
     * @throws TokenException If an error occurs during sending request and processing the response.
     */
    TokenResponse processTokenResponse(HTTPRequest request, OIDCConfiguration oidcConfiguration) throws TokenException {
        TokenResponse tokenResponse = new TokenResponse();
        HTTPResponse response;
        try {
            response = request.send();
        } catch (IOException e) {
            throw new TokenException("Error occured while sending the token request", e);
        }

        JSONObject responseObject;
        try {
            responseObject = response.getContentAsJSONObject();
        } catch (ParseException e) {
            throw new TokenException("Received token response is not a valid JSON object.", e);
        }

        if ((responseObject.get(Constants.ERROR)) != null) {
            return tokenResponse;
        }

        OIDCTokenResponse oidcTokenResponse;
        try {
            oidcTokenResponse = OIDCTokenResponse.parse(response);
        } catch (ParseException e) {
            throw new TokenException("Error occured while parsing the received response to oidc token response.", e);
        }

        IDTokenClaimsSet claimsSet;
        try {
            claimsSet = validateIDToken(oidcConfiguration, oidcTokenResponse);
        } catch (TokenException e) {
            throw new TokenException("Error occurred while getting the id token claim set.", e);
        }

        tokenResponse.setAccessToken(oidcTokenResponse.getOIDCTokens().getAccessToken().toString());
        tokenResponse.setRefreshToken(oidcTokenResponse.getOIDCTokens().getRefreshToken().toString());
        tokenResponse.setIdToken(oidcTokenResponse.getOIDCTokens().getIDTokenString());
        tokenResponse.setTokenType(oidcTokenResponse.toJSONObject().get(Constants.TOKEN_TYPE).toString());
        tokenResponse.setExpiresIn(oidcTokenResponse.toJSONObject().get(Constants.EXPIRES_IN).toString());
        tokenResponse.setIdTokenClaimSet(claimsSet.toJSONObject().toJSONString());
        return tokenResponse;
    }

    /**
     * This is a default method used to validate the token response using the id token claims and signature which is
     * called by {@code processTokenResponse}.
     *
     * @param oidcConfiguration Configurations specific to web application.
     * @param oidcTokenResponse The received {@link OIDCTokenResponse}.
     * @return The {@link IDTokenClaimsSet} if the validation is successful.
     * @throws TokenException If an error occurs during the validation.
     */
    private IDTokenClaimsSet validateIDToken(OIDCConfiguration oidcConfiguration, OIDCTokenResponse oidcTokenResponse)
            throws TokenException {
        OIDCConfiguration.TrustStore store = oidcConfiguration.getTruststore();
        Issuer issuer = new Issuer(oidcConfiguration.getTokenEndpoint());
        ClientID clientID = new ClientID(oidcConfiguration.getClientID());
        JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
        RSAPublicKey publicKey;
        InputStream file;
        try {
            file = new FileInputStream(store.getLocation());
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(file, store.getPassword().toCharArray());
            String alias = store.getKeyAlias();
            Certificate cert;
            cert = keystore.getCertificate(alias);
            publicKey = (RSAPublicKey) cert.getPublicKey();
            file.close();
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            throw new TokenException("Error occurred while obtaining the public key.", e);
        }

        Map<String, String> jwkMap = new HashMap<>();
        jwkMap.put(Constants.KEY_TYPE, publicKey.getAlgorithm());
        jwkMap.put(Constants.X509_CERTIFICATE_SHA_1_THUMBPRINT, Constants.X509_CERTIFICATE_SHA_1_THUMBPRINT_VALUE);
        jwkMap.put(Constants.KEY_ID, Constants.KEY_ID_VALUE);
        jwkMap.put(Constants.ALGORITHM, Constants.ALGORITHM_TYPE);
        jwkMap.put(Constants.MODULUS, String.valueOf(Base64URL.encode(publicKey.getModulus())));
        jwkMap.put(Constants.EXPONENT, String.valueOf(Base64URL.encode(publicKey.getPublicExponent())));
        JWK jwk;
        try {
            jwk = JWK.parse(new JSONObject(jwkMap));
        } catch (java.text.ParseException e) {
            throw new TokenException("Error occurred while generating the JKW.", e);
        }

        JWKSet jwkSet = new JWKSet(jwk);
        IDTokenValidator idTokenValidator = new IDTokenValidator(issuer, clientID, jwsAlg, jwkSet);
        IDTokenClaimsSet claimsSet;
        try {
            claimsSet = idTokenValidator.validate(oidcTokenResponse.getOIDCTokens().getIDToken(), null);
        } catch (BadJOSEException | JOSEException e) {
            throw new TokenException("Error occurred while validating the ID Token.", e);
        }

        return claimsSet;
    }

    /**
     * This method generates User Info request, makes direct call to User Info endpoint at authorization server,
     * gets the user info response, processes it and return it.
     *
     * @param oidcConfiguration Configurations specific to web application.
     * @param acsToken          A string value of access token, received in token response.
     * @return {@link UserInformationResponse} Object with received values.
     * @throws UserInfoException If an error occurs during getting the user information.
     */
    public UserInformationResponse getUserInfo(OIDCConfiguration oidcConfiguration, String acsToken)
            throws UserInfoException {
        BearerAccessToken accessToken = new BearerAccessToken(acsToken);
        URI userInfoEndpoint = oidcConfiguration.getUserInfoEndpoint();
        UserInfoRequest userInfoRequest = new UserInfoRequest(userInfoEndpoint, accessToken);
        HTTPRequest request = userInfoRequest.toHTTPRequest();
        return processUserInfoResponse(request);
    }

    /**
     * This is a default method which sends the user info request and processes the received response which is called by
     * the method getUserInfo.
     *
     * @param request Generated user info request.
     * @return {@link UserInformationResponse} Object with received values.
     * @throws UserInfoException If an error occurs during getting the user information.
     */
    UserInformationResponse processUserInfoResponse(HTTPRequest request) throws UserInfoException {
        UserInformationResponse userInformationResponse = new UserInformationResponse();
        UserInfoResponse response;
        try {
            response = com.nimbusds.openid.connect.sdk.UserInfoResponse.parse(request.send());
        } catch (ParseException | IOException e) {
            throw new UserInfoException("Error occured while getting the user info response.", e);
        }

        if (response instanceof UserInfoErrorResponse) {
            return userInformationResponse;
        }

        UserInfoSuccessResponse userInfoSuccessResponse = (UserInfoSuccessResponse) response;
        userInformationResponse.setUserInfo(userInfoSuccessResponse.getUserInfo().toJSONObject().toJSONString());
        return userInformationResponse;
    }

    /**
     * Generates the logout request and return it as a string.
     *
     * @param oidcConfiguration Configurations specific to web application.
     * @param idTokenString     String value of id token, received in the token response.
     * @return String value of generated logout request.
     * @throws LogoutException If an error occurs during the generation of logout request.
     */
    public String buildLogoutRequest(OIDCConfiguration oidcConfiguration, String idTokenString)
            throws LogoutException {
        SignedJWT idToken;
        try {
            idToken = SignedJWT.parse(idTokenString);
        } catch (java.text.ParseException e) {
            throw new LogoutException("Error occurred while parsing the id token to signed jwt.", e);
        }

        LogoutRequest logoutRequest = new LogoutRequest(oidcConfiguration.getLogoutEndpoint(), idToken);
        return logoutRequest.toURI().toString();
    }
}
