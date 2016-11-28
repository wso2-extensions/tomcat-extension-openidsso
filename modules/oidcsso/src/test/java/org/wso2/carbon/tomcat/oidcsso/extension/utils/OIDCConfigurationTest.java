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

package org.wso2.carbon.tomcat.oidcsso.extension.utils;

import org.apache.catalina.Context;
import org.apache.catalina.Globals;
import org.apache.catalina.Host;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.core.StandardHost;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.tomcat.oidcsso.extension.Constants;
import org.wso2.carbon.tomcat.oidcsso.extension.TestConstants;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.OIDCConfigurationException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.OIDCConfigurationRuntimeException;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * This class defines unit-tests for OpenID Connect configurations.
 */
public class OIDCConfigurationTest {
    private static final Path catalina_base = Paths.get(TestConstants.TEST_RESOURCES, TestConstants.CATALINA_BASE);
    private static final Host host = new StandardHost();
    private static final Context sample_context = new StandardContext();
    private static final Context faulty_sample_context = new StandardContext();
    private static final Context no_context = new StandardContext();
    private static final StrSubstitutor string_sub = new StrSubstitutor(System.getenv());

    @BeforeClass
    public void setupCatalinaBaseEnv() throws IOException {
        System.setProperty(Globals.CATALINA_BASE_PROP, catalina_base.toString());
        prepareCatalinaComponents();
    }

    @Test(description = "Attempts to load XML file content of a non-existent webapp descriptor", priority = 1)
    public void testObjectLoadingFromNonExistentDescriptor() throws OIDCConfigurationRuntimeException {
        OIDCConfigurationLoader oidcConfigurationLoader = new OIDCConfigurationLoader();
        List<Lifecycle> components = new ArrayList<>();
        components.add(host);
        components.add(sample_context);
        components.forEach(component -> oidcConfigurationLoader.
                lifecycleEvent(new LifecycleEvent(component, Lifecycle.BEFORE_START_EVENT, null)));
    }

    @Test(description = "Loads the XML file content of a WSO2 App Server specific webapp descriptor", priority = 2)
    public void testObjectLoadingFromDescriptor() throws IOException, OIDCConfigurationException {
        OIDCConfigurationLoader oidcConfigurationLoader = new OIDCConfigurationLoader();
        oidcConfigurationLoader.
                lifecycleEvent(new LifecycleEvent(sample_context, Lifecycle.BEFORE_START_EVENT, null));
        Optional<OIDCConfiguration> effective = OIDCConfigurationLoader.getOIDCConfiguration(sample_context);
        if (effective.isPresent()) {
            Assert.assertTrue(compare(effective.get(), prepareOIDCConfiguration()));
        } else {
            Assert.fail();
        }
    }

    @Test(description = "Loads the XML file content of an erroneous webapp descriptor",
            expectedExceptions = {OIDCConfigurationRuntimeException.class}, priority = 3)
    public void testObjectLoadingFromFaultyDescriptor() {
        OIDCConfigurationLoader oidcConfigurationLoader = new OIDCConfigurationLoader();
        oidcConfigurationLoader.
                lifecycleEvent(new LifecycleEvent(faulty_sample_context, Lifecycle.BEFORE_START_EVENT, null));
    }

    @Test(description = "Checks the removal of per web app configurations at Lifecycle.AFTER_STOP_EVENT", priority = 4)
    public void testWebAppConfigurationUnloading() {
        OIDCConfigurationLoader oidcConfigurationLoader = new OIDCConfigurationLoader();
        oidcConfigurationLoader.
                lifecycleEvent(new LifecycleEvent(sample_context, Lifecycle.AFTER_STOP_EVENT, null));
        Optional<OIDCConfiguration> configuration = OIDCConfigurationLoader.
                getOIDCConfiguration(sample_context);
        Assert.assertFalse(configuration.isPresent());
    }

    @Test(description = "Attempts to load the XML file content with a non-existent XML schema file for validation",
            expectedExceptions = {OIDCConfigurationException.class}, priority = 5)
    public void testLoadingObjectFromNonExistentSchemaAsPath()
            throws IOException, OIDCConfigurationException {
        OIDCConfigurationLoader oidcConfigurationLoader = new OIDCConfigurationLoader();
        Path xmlSource = Paths.get(TestConstants.TEST_RESOURCES, Constants.WEBAPP_DESCRIPTOR);
        Path xmlSchema = Paths.get(TestConstants.TEST_RESOURCES, TestConstants.NON_EXISTENT_SCHEMA);
        oidcConfigurationLoader.getUnmarshalledObject(xmlSource, xmlSchema, OIDCConfiguration.class);
    }

    @Test(description = "Uses an invalid XML schema file for validation",
            expectedExceptions = {OIDCConfigurationException.class}, priority = 6)
    public void testLoadingObjectWithInvalidSchema() throws IOException, OIDCConfigurationException {
        OIDCConfigurationLoader oidcConfigurationLoader = new OIDCConfigurationLoader();
        Path xmlSchema = Paths.get(TestConstants.TEST_RESOURCES, TestConstants.INVALID_SCHEMA_FILE);
        oidcConfigurationLoader.getXMLUnmarshaller(xmlSchema, OIDCConfiguration.class);
    }

    @Test(description = "Attempts to load content from a file source with invalid XML syntax",
            expectedExceptions = {OIDCConfigurationException.class}, priority = 7)
    public void testLoadingObjectFromInvalidFile() throws IOException, OIDCConfigurationException {
        OIDCConfigurationLoader oidcConfigurationLoader = new OIDCConfigurationLoader();
        Path xmlSource = Paths.get(TestConstants.TEST_RESOURCES, TestConstants.INVALID_DESCRIPTOR);
        Path xmlSchema = Paths.get(TestConstants.TEST_RESOURCES, Constants.WEBAPP_DESCRIPTOR_SCHEMA);
        oidcConfigurationLoader.getUnmarshalledObject(xmlSource, xmlSchema, OIDCConfiguration.class);
    }

    private static void prepareCatalinaComponents() {
        host.setAppBase(TestConstants.WEB_APP_BASE);
        sample_context.setParent(host);
        sample_context.setDocBase(TestConstants.SAMPLE_WEB_APP);
        faulty_sample_context.setParent(host);
        faulty_sample_context.setDocBase(TestConstants.FAULTY_SAMPLE_WEB_APP);
        no_context.setParent(host);
        no_context.setDocBase(TestConstants.NO_WEB_APP);
    }

    private static OIDCConfiguration prepareOIDCConfiguration() {
        OIDCConfiguration oidcConfiguration = new OIDCConfiguration();

        oidcConfiguration.setEnable(true);
        oidcConfiguration.setClientID(TestConstants.CLIENT_ID);
        oidcConfiguration.setClientSecret(TestConstants.CLIENT_SECRET);
        oidcConfiguration.setRedirectURI(URI.create(TestConstants.REDIRECT_URI));
        oidcConfiguration.setScope(TestConstants.SCOPE);
        oidcConfiguration.setClaims(TestConstants.CLAIMS);
        oidcConfiguration.setResponseType(TestConstants.RESPONSE_TYPE);
        oidcConfiguration.setGrantType(TestConstants.GRANT_TYPE);
        oidcConfiguration.setAuthenticationEndpoint(URI.create(TestConstants.AUTHENTICATION_ENDPOINT));
        oidcConfiguration.setTokenEndpoint(URI.create(TestConstants.TOKEN_ENDPOINT));
        oidcConfiguration.setUserInfoEndpoint(URI.create(TestConstants.USER_INFO_ENDPOINT));
        oidcConfiguration.setLogoutEndpoint(URI.create(TestConstants.LOGOUT_ENDPOINT));

        OIDCConfiguration.TrustStore truststore = new OIDCConfiguration.TrustStore();
        truststore.setLocation(TestConstants.TRUSTSTORE_PATH);
        truststore.setType(TestConstants.TYPE);
        truststore.setPassword(TestConstants.TRUSTSTORE_PASSWORD);
        truststore.setKeyAlias(TestConstants.PRIVATE_KEY_ALIAS);
        oidcConfiguration.setTruststore(truststore);
        truststore.setLocation(string_sub.replace(oidcConfiguration.getTruststore().getLocation()));
        truststore.setLocation(StrSubstitutor
                .replaceSystemProperties(oidcConfiguration.getTruststore().getLocation()));
        return oidcConfiguration;
    }

    private static boolean compare(OIDCConfiguration actual, OIDCConfiguration expected) {
        if ((actual != null) && (expected != null)) {
            boolean enable = actual.isEnabled().equals(expected.isEnabled());
            boolean clientID = actual.getClientID().trim().equals(expected.getClientID());
            boolean clientSecret = actual.getClientSecret().trim().equals(expected.getClientSecret());
            boolean redirectURI = actual.getRedirectURI().equals(expected.getRedirectURI());
            boolean scope = actual.getScope().trim().equals(expected.getScope());
            boolean claims = actual.getClaims().trim().equals(expected.getClaims());
            boolean responseType = actual.getResponseType().trim().equals(expected.getResponseType());
            boolean grantType = actual.getGrantType().trim().equals(expected.getGrantType());
            boolean authenticationEndpoint = actual.getAuthenticationEndpoint()
                    .equals(expected.getAuthenticationEndpoint());
            boolean tokenEndpoint = actual.getTokenEndpoint().equals(expected.getTokenEndpoint());
            boolean userInfoEndpoint = actual.getUserInfoEndpoint().equals(expected.getUserInfoEndpoint());
            boolean logoutEndpoint = actual.getLogoutEndpoint().equals(expected.getLogoutEndpoint());
            boolean security = comparetrustStoreConfigurations(actual.getTruststore(),
                    expected.getTruststore());
            return (enable && clientID && clientSecret && redirectURI && scope && claims && responseType && grantType
                    && authenticationEndpoint && tokenEndpoint && userInfoEndpoint && logoutEndpoint && security);
        } else {
            return ((actual == null) && (expected == null));
        }
    }

    private static boolean comparetrustStoreConfigurations(OIDCConfiguration.TrustStore actual,
                                                           OIDCConfiguration.TrustStore expected) {
        if ((actual != null) && (expected != null)) {
            boolean truststorePath = actual.getLocation().trim().equals(expected.getLocation());
            boolean truststorePassword = actual.getPassword().trim().equals(expected.getPassword());
            boolean truststoreType = actual.getType().trim().equals(expected.getType());
            return (truststorePath && truststorePassword && truststoreType);
        } else {
            return (actual == null) && (expected == null);
        }
    }
}
