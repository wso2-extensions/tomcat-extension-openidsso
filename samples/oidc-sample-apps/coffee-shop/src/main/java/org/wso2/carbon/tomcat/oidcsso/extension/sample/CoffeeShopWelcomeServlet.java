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

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Welcome servlet of a sample web app which redirects to sign in to the web app.
 */
public class CoffeeShopWelcomeServlet extends HttpServlet {

    private static final long serialVersionUID = 5500089023228705151L;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        PrintWriter out = resp.getWriter();
        out.println("<HTML>");
        out.println("<HEAD>");
        out.println("<TITLE>coffee-shop</TITLE>");
        out.println("</HEAD>");
        out.println("<BODY>");
        out.print("<p>");
        out.print("<h2> Welcome to coffee-shop </h2>");
        out.print("</p>");
        out.print("<p>");
        out.print("<a href=\"http://localhost:8080/coffee-shop/signin\">SignIn</a>\n");
        out.print("</p>");
        out.println("</BODY>");
        out.println("</HTML>");
    }
}
