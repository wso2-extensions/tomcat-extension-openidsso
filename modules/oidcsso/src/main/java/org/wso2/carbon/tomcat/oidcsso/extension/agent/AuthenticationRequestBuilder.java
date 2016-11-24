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

package org.wso2.carbon.tomcat.oidcsso.extension.agent;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import org.wso2.carbon.tomcat.oidcsso.extension.Constants;
import org.wso2.carbon.tomcat.oidcsso.extension.oidc.StateStore;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.AuthenticationRequestException;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * A Java class which defines the parameters required to generate an OpenID Connect authentication request.
 */
final class AuthenticationRequestBuilder {
    private URI authenticationEndpoint;
    private URI redirectURI;
    private String clientID;
    private String scope = null;
    private String claims = null;
    private String responseType;
    private String state = null;
    private Map<String, String> customParameters = null;

    void setAuthenticationEndpoint(URI authenticationEndpoint) {
        this.authenticationEndpoint = authenticationEndpoint;
    }

    void setRedirectURI(URI redirectURI) {
        this.redirectURI = redirectURI;
    }

    void setClientID(String clientID) {
        this.clientID = clientID;
    }

    void setScope(String scope) {
        this.scope = scope;
    }

    void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    void setState(String state) {
        this.state = state;
    }

    void setClaims(String claims) {
        this.claims = claims;
    }

    void setCustomParameters(Map<String, String> customParameters) {
        this.customParameters = customParameters;
    }

    /**
     * This nested class builds the Authentication Request Using "Nimbus OAuth 2.0 SDK with OpenID Connect extensions"
     * library
     *
     * @param stateStore storage for state values which is used to validate the authentication response
     * @return Authentication Request String
     */
    String build(StateStore stateStore) throws AuthenticationRequestException {
        List<String> scopeList = Arrays.asList(scope.split("\\s*,\\s*"));
        List<String> claimsList = Arrays.asList(claims.split("\\s*,\\s*"));
        ResponseType responseType1 = new ResponseType(responseType);
        Scope scope1 = new Scope(Scope.parse(scopeList));
        ClientID clientID1 = new ClientID(clientID);
        State state1;
        if (state == null) {
            state1 = new State(Constants.STATE_LENGTH);
        } else {
            state1 = new State(state);
        }
        stateStore.storeState(String.valueOf(state1));
        ClaimsRequest claimsRequest = new ClaimsRequest();
        claimsList.forEach(claimsRequest::addUserInfoClaim);
        AuthenticationRequest.Builder authenticationRequest;
        try {
            authenticationRequest = new AuthenticationRequest.Builder(responseType1, scope1, clientID1, redirectURI);
        } catch (IllegalArgumentException e) {
            throw new
                    AuthenticationRequestException("Error occurred while creating a authentication request builder", e);
        }
        authenticationRequest.endpointURI(authenticationEndpoint);
        authenticationRequest.state(state1);
        authenticationRequest.claims(claimsRequest);
        if (customParameters != null) {
            customParameters.forEach((key, value) -> authenticationRequest
                    .customParameter(String.valueOf(key), String.valueOf(value)));
        }
        AuthenticationRequest authRequest = authenticationRequest.build();
        return authRequest.toURI().toString();
    }
}
