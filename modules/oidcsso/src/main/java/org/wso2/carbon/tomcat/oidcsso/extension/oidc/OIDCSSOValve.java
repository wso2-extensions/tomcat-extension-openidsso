/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.wso2.carbon.tomcat.oidcsso.extension.oidc;

import org.apache.catalina.authenticator.SingleSignOn;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.wso2.carbon.tomcat.oidcsso.extension.Constants;
import org.wso2.carbon.tomcat.oidcsso.extension.agent.OIDCAgent;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.AuthenticationResponse;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.OIDCLoggedInSession;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.RequestParameters;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.TokenResponse;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.UserInfoResponse;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.OIDCConfiguration;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.OIDCConfigurationLoader;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.AuthenticationRequestException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.AuthenticationResponseException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.LogoutException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.TokenException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.UserInfoException;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.servlet.ServletException;

/**
 * This class implements an OpenID Connect valve for tomcat, which performs OpenID Connect based single-sign-on (SSO)
 * and single-logout (SLO) functions.
 */
public class OIDCSSOValve extends SingleSignOn {
    private static final Log log = LogFactory.getLog(OIDCSSOValve.class);
    private OIDCAgent oidcAgent = new OIDCAgent();
    private StateStore stateStore = new InMemoryStateStore();

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        Optional<OIDCConfiguration> configuration = OIDCConfigurationLoader.getOIDCConfiguration(request.getContext());
        OIDCConfiguration oidcContextConfiguration;
        if (configuration.isPresent()) {
            oidcContextConfiguration = configuration.get();
            if (oidcContextConfiguration == null) {
                getNext().invoke(request, response);
                return;
            }
        } else {
            getNext().invoke(request, response);
            return;
        }
        if (!oidcContextConfiguration.isEnabled()) {
            getNext().invoke(request, response);
            return;
        }
//        checks whether the request is a initial request to start the oidc flow by sending authentication request
//        to openid provider
        if ((request.getRequestURI().endsWith(Constants.SIGN_IN)) && ((request.getSession(false) == null)
                || (request.getSession(false).getAttribute(Constants.SESSION_BEAN) == null))) {
            String authenticationRequest = null;
            try {
                authenticationRequest = handleUnAuthenticatedRequest(request, oidcContextConfiguration);
            } catch (AuthenticationRequestException e) {
                log.error("Error occurred while building the authentication request.", e);
                getNext().invoke(request, response);
            }
            request.getSession(true);
            response.sendRedirect(authenticationRequest);
            return;
        }
//        checks whether the request is sent by the RP iFrame to send re-authentication request
        if (request.getRequestURI().endsWith(Constants.RE_AUTHENTICATE)) {
            String reAuthenticationRequest = null;
            try {
                reAuthenticationRequest = handleReAuthenticationRequest(oidcContextConfiguration);
            } catch (AuthenticationRequestException e) {
                log.error("Error occurred while building the re-authentication request.", e);
                getNext().invoke(request, response);
            }
            response.sendRedirect(reAuthenticationRequest);
            return;
        }
//        checks whether the request is an authentication response from the openid provider
        if (request.getRequestURI().endsWith(Constants.OPENID)) {
//            checks whether the response is for the re-authentication request.
            if (request.getSession(false).getAttribute(Constants.SESSION_BEAN) != null) {
                handleReAuthenticationResponse(request, response, oidcContextConfiguration);
                return;
            }
            OIDCLoggedInSession loggedInSession = new OIDCLoggedInSession();
            AuthenticationResponse authenticationResponse = new AuthenticationResponse();
            try {
                authenticationResponse = handleAuthenticationResponse(request);
            } catch (AuthenticationResponseException e) {
                log.error("Error occurred while processing the authentication response.", e);
                getNext().invoke(request, response);
            }
            if (authenticationResponse.getCode() == null) {
                getNext().invoke(request, response);
                return;
            }
            request.getSession(false).setAttribute(Constants.SESSION_STATE, authenticationResponse
                    .getSessionState());
            request.getSession(false).setAttribute(Constants.CLIENT_ID, oidcContextConfiguration.getClientID());

            TokenResponse tokenResponse = new TokenResponse();
            try {
                tokenResponse = handleTokenResponse(oidcContextConfiguration,
                        authenticationResponse.getCode());
            } catch (TokenException e) {
                log.error("Error occurred while receiving the token response.", e);
                getNext().invoke(request, response);
            }
            if (tokenResponse.getAccessToken() == null) {
                getNext().invoke(request, response);
                return;
            }
            loggedInSession.setAccessToken(tokenResponse.getAccessToken());
            loggedInSession.setRefreshToken(tokenResponse.getRefreshToken());
            loggedInSession.setIdToken(tokenResponse.getIdToken());
            loggedInSession.setIdTokenClaimSet(tokenResponse.getIdTokenClaimSet());
            request.getSession(false).setAttribute(Constants.SESSION_BEAN, loggedInSession);

            UserInfoResponse userInfoResponse = new UserInfoResponse();
            try {
                userInfoResponse = handleUserInfoResponse(oidcContextConfiguration,
                        tokenResponse.getAccessToken());
            } catch (UserInfoException e) {
                log.error("Error occurred while receiving the user info response.", e);
                getNext().invoke(request, response);
            }
            if (userInfoResponse.getUserInfo() == null) {
                getNext().invoke(request, response);
                return;
            }
            request.getSession(false).setAttribute(Constants.USER_INFO_RESPONSE, userInfoResponse.getUserInfo());
            getNext().invoke(request, response);
            return;
        }
//        checks whether the request is to send logout request
        if ((request.getRequestURI().endsWith(Constants.LOGOUT)) && (request.getSession(false) != null)) {
            String logoutRequest = null;
            try {
                logoutRequest = handleLogoutRequest(request, oidcContextConfiguration);
            } catch (LogoutException e) {
                log.error("Error occurred while building the logout request.", e);
                getNext().invoke(request, response);
            }
            request.getSession(false).invalidate();
            response.sendRedirect(logoutRequest);
            return;
        }
        getNext().invoke(request, response);
    }

    /**
     * this is a protected method which handles the initial request to prepare authentication request
     * @param request received httpServletRequest
     * @param oidcContextConfiguration webapp specific configuration
     * @return authentication request string
     * @throws AuthenticationRequestException if any error occurs during building the authentication request string
     */
    protected String handleUnAuthenticatedRequest(Request request, OIDCConfiguration oidcContextConfiguration)
            throws AuthenticationRequestException {
        RequestParameters requestParameters = new RequestParameters();
        if (request.getAttribute(Constants.SCOPE) != null) {
            requestParameters.setScope(String.valueOf(request.getAttribute(Constants.SCOPE)));
        }
        if (request.getAttribute(Constants.CLAIMS) != null) {
            requestParameters.setClaims(String.valueOf(request.getAttribute(Constants.CLAIMS)));
        }
        if (request.getAttribute(Constants.STATE) != null) {
            requestParameters.setClaims(String.valueOf(request.getAttribute(Constants.STATE)));
        }
        if (request.getAttribute(Constants.CUSTOM_PARAMETERS) != null) {
            requestParameters.setCustomParameters((Map<String, String>) request
                    .getAttribute(Constants.CUSTOM_PARAMETERS));
        }
        String authenticationRequestURI;
        authenticationRequestURI = oidcAgent.buildAuthenticationRequest(oidcContextConfiguration,
                requestParameters, stateStore);
        return authenticationRequestURI;
    }

    /**
     * this is a protected method which handles the request to prepare re-authentication request
     * @param oidcContextConfiguration webapp specific configuration
     * @return re-authentication request string
     * @throws AuthenticationRequestException if any error occurs during building the re-authentication request string
     */
    protected String handleReAuthenticationRequest(OIDCConfiguration oidcContextConfiguration)
            throws AuthenticationRequestException {
        RequestParameters requestParameters = new RequestParameters();
        Map<String, String> customParameters = new HashMap<>();
        customParameters.put(Constants.PROMPT, Constants.NONE);
        requestParameters.setCustomParameters(customParameters);
        String reAuthenticateRequest;
        reAuthenticateRequest = oidcAgent.buildAuthenticationRequest(oidcContextConfiguration,
                requestParameters, stateStore);
        return reAuthenticateRequest;
    }

    /**
     * this is a protected method which handles the re-authentication response.
     * @param request received http servlet request
     * @param response http servlet response
     * @param oidcContextConfiguration webapp specific configuration
     * @throws IOException if any error occurs during invoking the next valve
     * @throws ServletException if any error occurs during invoking the next valve or redirection
     */
    protected void handleReAuthenticationResponse(Request request, Response response,
                                                  OIDCConfiguration oidcContextConfiguration)
            throws IOException, ServletException {
        Map<String, String> queryString = new HashMap<>();
        Enumeration params = request.getParameterNames();
        while (params.hasMoreElements()) {
            String name = (String) params.nextElement();
            queryString.put(name, request.getParameter(name));
        }
        if (queryString.get(Constants.ERROR) != null) {
            if (queryString.get(Constants.ERROR).equals(Constants.ACCESS_DENIED)) {
                request.getSession(false).setAttribute(Constants.SESSION_STATE,
                        queryString.get(Constants.SESSION_STATE));
                getNext().invoke(request, response);
                return;
            }
            if (queryString.get(Constants.ERROR).equals(Constants.LOGIN_REQUIRED)) {
                request.getSession(false).invalidate();
                response.sendRedirect(Constants.SERVER_URL + request.getContextPath());
                return;
            }
        }
        if (queryString.get(Constants.CODE) != null) {
            request.getSession(false).setAttribute(Constants.SESSION_STATE,
                    queryString.get(Constants.SESSION_STATE));
            request.getSession(false).setAttribute(Constants.CLIENT_ID,
                    oidcContextConfiguration.getClientID());
            getNext().invoke(request, response);
        }
    }

    /**
     * this is a protected method which handles the authentication response.
     * @param request received http servlet request
     * @return authentication response object
     * @throws AuthenticationResponseException if any error occurs during processing the response
     */
    protected AuthenticationResponse handleAuthenticationResponse(Request request)
            throws AuthenticationResponseException {
        AuthenticationResponse authenticationResponse;
        authenticationResponse = oidcAgent.processAuthenticationResponse(request, stateStore);
        return authenticationResponse;
    }

    /**
     * this is a protected method which handles the token request and response.
     * @param oidcContextConfiguration webapp specific configuration
     * @param code authorization code received in the authentication response
     * @return the token response object
     * @throws TokenException if any error occurs during the process
     */
    protected TokenResponse handleTokenResponse(OIDCConfiguration oidcContextConfiguration, String code)
            throws TokenException {
        TokenResponse tokenResponse;
        tokenResponse = oidcAgent.getTokenResponse(oidcContextConfiguration, code);
        return tokenResponse;
    }

    /**
     * this is a protected method which handles the user-info request and response.
     * @param oidcContextConfiguration webapp specific configuration
     * @param accessToken received value in the token response
     * @return the user info response object
     * @throws UserInfoException if any error occurs during the process
     */
    protected UserInfoResponse handleUserInfoResponse(OIDCConfiguration oidcContextConfiguration, String accessToken)
            throws UserInfoException {
        UserInfoResponse userInfoResponse;
        userInfoResponse = oidcAgent.getUserInfo(oidcContextConfiguration, accessToken);
        return userInfoResponse;
    }

    /**
     * this is a protected method which handles the logout request.
     * @param request received http servlet request
     * @param oidcContextConfiguration webapp specific configuration
     * @return the log out request string
     * @throws LogoutException if any error occurs during the process
     */
    protected String handleLogoutRequest(Request request, OIDCConfiguration oidcContextConfiguration)
            throws LogoutException {
        OIDCLoggedInSession loggedInSession = (OIDCLoggedInSession) request.getSession(false)
                .getAttribute(Constants.SESSION_BEAN);
        String logoutRequest;
        logoutRequest = oidcAgent.buildLogoutRequest(oidcContextConfiguration, loggedInSession.getIdToken());
        return logoutRequest;
    }
}

