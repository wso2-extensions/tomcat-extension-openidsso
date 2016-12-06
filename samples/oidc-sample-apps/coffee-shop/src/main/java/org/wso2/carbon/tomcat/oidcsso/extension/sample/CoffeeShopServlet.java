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
package org.wso2.carbon.tomcat.oidcsso.extension.sample;

import org.wso2.carbon.tomcat.oidcsso.extension.Constants;
import org.wso2.carbon.tomcat.oidcsso.extension.bean.OIDCLoggedInSession;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This is a sample java Servlet class to show the responses of OpenId Connect flow of the web app.
 */
public class CoffeeShopServlet extends HttpServlet {
    private static final long serialVersionUID = -7272130203914249633L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        OIDCLoggedInSession object = (OIDCLoggedInSession) request.getSession(false)
                .getAttribute(Constants.SESSION_BEAN);
        String userInfoSuccessResponse = (String) request.getSession(false).getAttribute(Constants.USER_INFO_RESPONSE);

        PrintWriter out = response.getWriter();
        out.println("<HTML>");
        out.println("<HEAD>");
        out.println("<TITLE>coffee-shop</TITLE>");
        out.println("</HEAD>");
        out.println("<BODY>");
        out.print("<p>");
        if (object != null) {
            out.println("successfully logged in <br />");
            out.print("<br />");
            out.println("Access Token : " + object.getAccessToken() + "<br />");
            out.print("<br />");
            out.print("Refresh Token : " + object.getRefreshToken() + "<br />");
            out.print("<br />");
            out.print("ID Token : " + object.getIdToken() + "<br />");
            out.print("<br />");
            out.print("ID Token Claim Set : " + object.getIdTokenClaimSet() + "<br />");
            out.print("<br />");
        }
        if (userInfoSuccessResponse != null) {
            out.print("User Info : " + userInfoSuccessResponse + "<br />");
            out.print("<br />");
        }
        out.print("</p>");
        out.print("<p>");
        out.print("<a href=\"http://localhost:8080/coffee-shop/logout\">Logout</a>\n");
        out.print("</p>");
        out.print("<iframe id=\"rpIFrame\" src=\"rpiFrame.jsp\" frameborder=\"0\" width=\"0\" height=\"0\"></iframe>");
        out.println("</BODY>");
        out.println("</HTML>");
    }
}
