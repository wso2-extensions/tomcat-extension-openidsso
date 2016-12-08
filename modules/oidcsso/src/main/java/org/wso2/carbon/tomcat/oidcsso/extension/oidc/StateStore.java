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

package org.wso2.carbon.tomcat.oidcsso.extension.oidc;

import java.util.List;

/**
 * This interface defines the storage of state values in the authentication request of OpenID Connect.
 */
public interface StateStore {

    /**
     * Inserts the state value to the defined storage.
     *
     * @param stateValue String value of the state to be stored.
     */
    void storeState(String stateValue);

    /**
     * Returns the list of stored state values.
     *
     * @return the list of state values.
     */
    List<String> getStates();
}
