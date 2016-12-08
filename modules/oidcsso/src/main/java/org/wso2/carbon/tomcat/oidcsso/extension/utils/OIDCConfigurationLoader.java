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

import org.apache.catalina.Context;
import org.apache.catalina.Globals;
import org.apache.catalina.Host;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.wso2.carbon.tomcat.oidcsso.extension.Constants;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.OIDCConfigurationException;
import org.wso2.carbon.tomcat.oidcsso.extension.utils.exception.OIDCConfigurationRuntimeException;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

/**
 * A class which loads WSO2 specific context level configurations for all contexts.
 */
public class OIDCConfigurationLoader implements LifecycleListener {
    private static OIDCConfiguration oidcConfiguration;
    private static final Map<Context, OIDCConfiguration> contextToConfigurationMap =
            new ConcurrentHashMap<>();

    private static String catalinaBase = System.getProperty(Globals.CATALINA_BASE_PROP);
    private static final Path PATH_CATALINA_BASE = Paths.get(catalinaBase);
    private static final Path PATH_APP_SERVER_CONFIG_BASE = Paths
            .get(catalinaBase, Constants.TOMCAT_CONFIGURATION_DIRECTORY, Constants.OIDC_CONFIGURATION_DIRECTORY);

    /**
     * Retrieves the {@code OIDCConfiguration} matching the specified context.
     *
     * @param context The context for which the matching {@link OIDCConfiguration} is to be returned.
     * @return The {@link OIDCConfiguration} matching the specified context.
     */
    public static Optional<OIDCConfiguration> getOIDCConfiguration(Context context) {
        oidcConfiguration = contextToConfigurationMap.get(context);
        return Optional.ofNullable(oidcConfiguration);
    }

    /**
     * Processes {@code Context}s at "configure_start" event to retrieve a final set of WSO2 specific
     * context level configurations.
     * <p>
     * For the purpose of generating the effective set of configurations, the global and context level webapp
     * descriptor files are read, if available.
     *
     * @param lifecycleEvent The lifecycle event that has occurred.
     */
    @Override
    public void lifecycleEvent(LifecycleEvent lifecycleEvent) {
        Object source;
        if (Lifecycle.BEFORE_START_EVENT.equals(lifecycleEvent.getType())) {
            source = lifecycleEvent.getSource();
            if (source instanceof Context) {
                Context context = (Context) source;
                OIDCConfiguration effectiveConfiguration = getEffectiveConfiguration(context);
                contextToConfigurationMap.put(context, effectiveConfiguration);
            }
        } else if (Lifecycle.AFTER_STOP_EVENT.equals(lifecycleEvent.getType())) {
            source = lifecycleEvent.getSource();
            if (source instanceof Context) {
                Context context = (Context) source;
                contextToConfigurationMap.remove(context);
            }
        }
    }

    /**
     * Returns the final set of context level configurations for the specified context.
     * <p>
     * For this purpose, the context level configurations defined globally will be merged with context level
     * configurations overridden at the context level (if any).
     * If no configurations are overridden at context level, the global configurations will prevail.
     *
     * @param context The {@link Context} for which the final set of context level configurations are generated.
     * @return The final set of context level configurations for the specified {@link Context}.
     */
    private static OIDCConfiguration getEffectiveConfiguration(Context context)
            throws OIDCConfigurationRuntimeException {
        if (context != null) {
            Path schemaPath = Paths.
                    get(PATH_APP_SERVER_CONFIG_BASE.toString(), Constants.WEBAPP_DESCRIPTOR_SCHEMA);
            Path defaultWebAppDescriptor = Paths.
                    get(PATH_APP_SERVER_CONFIG_BASE.toString(), Constants.WEBAPP_DESCRIPTOR);
            OIDCConfiguration effective;
            try {
                Path localWebAppDescriptor = Paths.get(getWebAppPath(context).toString(),
                        Constants.WEB_CONTAINER_RESOURCE_FOLDER, Constants.WEBAPP_DESCRIPTOR);
                if (!Files.exists(defaultWebAppDescriptor)) {
                    throw new OIDCConfigurationRuntimeException(
                            "The " + defaultWebAppDescriptor.toString() + " does not exist");
                }

                effective = getUnmarshalledObject(defaultWebAppDescriptor, schemaPath,
                        OIDCConfiguration.class);
                if (Files.exists(localWebAppDescriptor)) {
                    OIDCConfiguration local = getUnmarshalledObject(localWebAppDescriptor,
                            schemaPath, OIDCConfiguration.class);
                    effective.merge(local);
                }
            } catch (OIDCConfigurationException e) {
                throw new OIDCConfigurationRuntimeException("Error when loading the context level configuration", e);
            }

            oidcConfiguration = effective;
            Optional.ofNullable(oidcConfiguration).ifPresent(OIDCConfiguration::resolveVariables);
            setSecuritySystemProperties();
            return effective;
        } else {
            throw new OIDCConfigurationRuntimeException("Context cannot be null");
        }
    }

    /**
     * Returns an absolute file path representation of the web app context root specified.
     *
     * @param context The webapp of which the context root is to be returned.
     * @return The absolute file path representation of the web app context root specified.
     * @throws OIDCConfigurationException If an IOException occurs when retrieving the context root.
     */
    private static Path getWebAppPath(Context context) throws OIDCConfigurationException {
        String webappFilePath = "";

        //  Value of the following variable depends on various conditions. Sometimes you get just the webapp directory
        //  name. Sometime you get absolute path the web app directory or war file.
        try {
            if (context != null) {
                String docBase = context.getDocBase();
                Host host = (Host) context.getParent();
                String appBase = host.getAppBase();
                File canonicalAppBase = new File(appBase);
                if (canonicalAppBase.isAbsolute()) {
                    canonicalAppBase = canonicalAppBase.getCanonicalFile();
                } else {
                    canonicalAppBase = new File(PATH_CATALINA_BASE.toString(), appBase)
                            .getCanonicalFile();
                }

                File webappFile = new File(docBase);
                if (webappFile.isAbsolute()) {
                    webappFilePath = webappFile.getCanonicalPath();
                } else {
                    webappFilePath = (new File(canonicalAppBase, docBase)).getPath();
                }
            }
        } catch (IOException e) {
            throw new OIDCConfigurationException("Error while generating web app file path", e);
        }
        return Paths.get(webappFilePath);
    }

    /**
     * Returns an XML unmarshaller for the defined Java classes.
     *
     * @param schemaPath File path of the XML schema file against which the source XML is to be validated.
     * @param classes    The list of classes to be recognized by the {@link JAXBContext}.
     * @return An XML unmarshaller for the defined Java classes.
     * @throws OIDCConfigurationException If an error occurs when creating the XML unmarshaller.
     */
    public static Unmarshaller getXMLUnmarshaller(Path schemaPath, Class... classes)
            throws OIDCConfigurationException {
        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(classes);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            if (Files.exists(schemaPath)) {
                SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
                Schema xmlSchema = schemaFactory.newSchema(schemaPath.toFile());
                unmarshaller.setSchema(xmlSchema);
            } else {
                throw new OIDCConfigurationException(
                        "Configuration schema not found in the file path: " + schemaPath.toString());
            }
            return unmarshaller;
        } catch (JAXBException | SAXException e) {
            throw new OIDCConfigurationException("Error when creating the XML unmarshaller", e);
        }
    }

    /**
     * Builds an XML binding from the XML source file specified.
     *
     * @param source       The XML source file path representation.
     * @param schema       An optional file path representation of an XML schema file against which the source XML
     *                     is to be validated.
     * @param bindingClass The class to be recognized by the {@link JAXBContext}.
     * @param <T>          The type of the class to be bound.
     * @return Bound object (Type T) of XML.
     * @throws OIDCConfigurationException If an error occurred when creating the unmarshaller or unmarshalling the
     *                                    XML source.
     */
    public static <T> T getUnmarshalledObject(Path source, Path schema, Class<T> bindingClass)
            throws OIDCConfigurationException {
        try {
            Unmarshaller unmarshaller = getXMLUnmarshaller(schema, bindingClass);
            Object unmarshalled = unmarshaller.unmarshal(source.toFile());
            return bindingClass.cast(unmarshalled);
        } catch (JAXBException e) {
            throw new OIDCConfigurationException("Error when unmarshalling the XML configuration", e);
        }
    }

    /**
     * Sets the system properties associated with Java SSL.
     */
    private static void setSecuritySystemProperties() {
        Optional.ofNullable(oidcConfiguration).ifPresent(configuration -> {
            OIDCConfiguration.TrustStore truststore = configuration.getTruststore();
            System.setProperty(Constants.JAVA_TRUST_STORE_LOCATION,
                    truststore.getLocation().replace("\\", "/"));
            System.setProperty(Constants.JAVA_TRUST_STORE_PASSWORD,
                    truststore.getPassword());
            System.setProperty(Constants.JAVA_TRUST_STORE_TYPE, truststore.getType());
        });
    }
}
