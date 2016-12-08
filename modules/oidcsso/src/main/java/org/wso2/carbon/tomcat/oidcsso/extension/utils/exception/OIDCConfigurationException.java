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

package org.wso2.carbon.tomcat.oidcsso.extension.utils.exception;

/**
 * This class defines a custom checked exception type specified for tomcat extension of openid sso which is thrown when
 * the extension encounters configuration related issues.
 */
public class OIDCConfigurationException extends Exception {

    public OIDCConfigurationException(String message) {
        super(message);
    }

    public OIDCConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
