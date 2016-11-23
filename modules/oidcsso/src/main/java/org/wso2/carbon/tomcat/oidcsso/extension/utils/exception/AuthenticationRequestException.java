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

package org.wso2.carbon.tomcat.oidcsso.extension.utils.exception;

/**
 * This class defines the exception type which is used in generating authentication request
 */
public class AuthenticationRequestException extends Exception {
    public AuthenticationRequestException(String message) {
        super(message);
    }

    public AuthenticationRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
