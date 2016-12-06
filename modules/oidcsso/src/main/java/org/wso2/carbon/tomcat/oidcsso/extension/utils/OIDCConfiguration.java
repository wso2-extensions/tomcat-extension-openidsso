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

package org.wso2.carbon.tomcat.oidcsso.extension.utils;

import org.apache.commons.lang3.text.StrSubstitutor;

import java.net.URI;
import java.util.Optional;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A class which models a holder for web application specific OpenId Connect configurations.
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "oidc-config")
public class OIDCConfiguration {
    @XmlElement(name = "enable")
    private Boolean enable;

    @XmlElement(name = "client-id")
    private String clientID;

    @XmlElement(name = "client-secret")
    private String clientSecret;

    @XmlElement(name = "redirect-uri")
    private URI redirectURI;

    @XmlElement(name = "scope")
    private String scope;

    @XmlElement(name = "claims")
    private String claims;

    @XmlElement(name = "response-type")
    private String responseType;

    @XmlElement(name = "grant-type")
    private String grantType;

    @XmlElement(name = "authentication-endpoint")
    private URI authenticationEndpoint;

    @XmlElement(name = "token-endpoint")
    private URI tokenEndpoint;

    @XmlElement(name = "user-info-endpoint")
    private URI userInfoEndpoint;

    @XmlElement(name = "logout-endpoint")
    private URI logoutEndpoint;

    @XmlElement(name = "trust-store")
    private TrustStore truststore;

    public Boolean isEnabled() {
        return enable;
    }

    public void setEnable(Boolean enable) {
        this.enable = enable;
    }

    public String getClientID() {
        return clientID;
    }

    public void setClientID(String clientID) {
        this.clientID = clientID;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public URI getRedirectURI() {
        return redirectURI;
    }

    public void setRedirectURI(URI redirectURI) {
        this.redirectURI = redirectURI;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getClaims() {
        return claims;
    }

    public void setClaims(String claims) {
        this.claims = claims;
    }

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public URI getAuthenticationEndpoint() {
        return authenticationEndpoint;
    }

    public void setAuthenticationEndpoint(URI authenticationEndpoint) {
        this.authenticationEndpoint = authenticationEndpoint;
    }

    public URI getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(URI tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public URI getUserInfoEndpoint() {
        return userInfoEndpoint;
    }

    public void setUserInfoEndpoint(URI userInfoEndpoint) {
        this.userInfoEndpoint = userInfoEndpoint;
    }

    public URI getLogoutEndpoint() {
        return logoutEndpoint;
    }

    public void setLogoutEndpoint(URI logoutEndpoint) {
        this.logoutEndpoint = logoutEndpoint;
    }

    public TrustStore getTruststore() {
        return truststore;
    }

    public void setTruststore(TrustStore truststore) {
        this.truststore = truststore;
    }

    /**
     * A nested class which defines the trust store configurations for Application Server.
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class TrustStore {
        @XmlElement(name = "location")
        private String location;

        @XmlElement(name = "type")
        private String type;

        @XmlElement(name = "key-alias")
        private String keyAlias;

        @XmlElement(name = "password")
        private String password;

        public String getLocation() {
            return location;
        }

        public void setLocation(String location) {
            this.location = location;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getKeyAlias() {
            return keyAlias;
        }

        public void setKeyAlias(String keyAlias) {
            this.keyAlias = keyAlias;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }

    /**
     * Merges the globally defined context level configurations and context level configurations overridden at
     * context level.
     *
     * @param configurations Group of context level configuration capable of being merged with this group.
     */
    void merge(OIDCConfiguration configurations) {
        Optional.ofNullable(configurations)
                .ifPresent(configs -> {
                    enable = Optional.ofNullable(configs.enable).orElse(enable);
                    clientID = Optional.ofNullable(configs.clientID).orElse(clientID);
                    clientSecret = Optional.ofNullable(configs.clientSecret).orElse(clientSecret);
                    redirectURI = Optional.ofNullable(configs.redirectURI).orElse(redirectURI);
                    scope = Optional.ofNullable(configs.scope).orElse(scope);
                    claims = Optional.ofNullable(configs.claims).orElse(claims);
                    responseType = Optional.ofNullable(configs.responseType).orElse(responseType);
                    grantType = Optional.ofNullable(configs.grantType).orElse(grantType);
                    authenticationEndpoint = Optional.ofNullable(configs.authenticationEndpoint)
                            .orElse(authenticationEndpoint);
                    tokenEndpoint = Optional.ofNullable(configs.tokenEndpoint).orElse(tokenEndpoint);
                    userInfoEndpoint = Optional.ofNullable(configs.userInfoEndpoint).orElse(userInfoEndpoint);
                    logoutEndpoint = Optional.ofNullable(configs.logoutEndpoint).orElse(logoutEndpoint);
                    truststore = Optional.ofNullable(configs.truststore).orElse(truststore);
                });
    }

    /**
     * Resolves the environmental and system variable placeholders specified among the configurations.
     */
    void resolveVariables() {
        resolveEnvVariables();
        resolveSystemProperties();
    }

    /**
     * Resolves the environmental variable placeholders specified among the configurations.
     */
    private void resolveEnvVariables() {
        StrSubstitutor strSubstitutor = new StrSubstitutor(System.getenv());
        truststore.setLocation(strSubstitutor.replace(truststore.getLocation()));
    }

    /**
     * Resolves the system variable placeholders specified among the configurations.
     */
    private void resolveSystemProperties() {
        truststore.setLocation(
                StrSubstitutor.replaceSystemProperties(truststore.getLocation()));
    }
}
