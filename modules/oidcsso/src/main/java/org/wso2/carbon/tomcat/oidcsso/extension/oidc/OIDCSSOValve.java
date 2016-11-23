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
        if (request.getRequestURI().endsWith(Constants.OPENID)) {
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

    protected String handleUnAuthenticatedRequest(Request request, OIDCConfiguration oidcContextConfiguration)
            throws ServletException, AuthenticationRequestException {
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

    protected String handleReAuthenticationRequest(OIDCConfiguration oidcContextConfiguration)
            throws ServletException, AuthenticationRequestException {
        RequestParameters requestParameters = new RequestParameters();
        Map<String, String> customParameters = new HashMap<>();
        customParameters.put(Constants.PROMPT, Constants.NONE);
        requestParameters.setCustomParameters(customParameters);
        String reAuthenticateRequest;

        reAuthenticateRequest = oidcAgent.buildAuthenticationRequest(oidcContextConfiguration,
                requestParameters, stateStore);
        return reAuthenticateRequest;
    }

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

    protected AuthenticationResponse handleAuthenticationResponse(Request request)
            throws IOException, ServletException, AuthenticationResponseException {
        AuthenticationResponse authenticationResponse;
        authenticationResponse = oidcAgent.processAuthenticationResponse(request, stateStore);
        return authenticationResponse;
    }

    protected TokenResponse handleTokenResponse(OIDCConfiguration oidcContextConfiguration, String code)
            throws IOException, ServletException, TokenException {
        TokenResponse tokenResponse;
        tokenResponse = oidcAgent.getTokenResponse(oidcContextConfiguration, code);
        return tokenResponse;
    }

    protected UserInfoResponse handleUserInfoResponse(OIDCConfiguration oidcContextConfiguration, String accessToken)
            throws IOException, ServletException, UserInfoException {
        UserInfoResponse userInfoResponse;
        userInfoResponse = oidcAgent.getUserInfo(oidcContextConfiguration, accessToken);
        return userInfoResponse;
    }

    protected String handleLogoutRequest(Request request, OIDCConfiguration oidcContextConfiguration)
            throws IOException, ServletException, LogoutException {
        OIDCLoggedInSession loggedInSession = (OIDCLoggedInSession) request.getSession(false)
                .getAttribute(Constants.SESSION_BEAN);
        String logoutRequest;
        logoutRequest = oidcAgent.buildLogoutRequest(oidcContextConfiguration, loggedInSession.getIdToken());
        return logoutRequest;
    }
}

