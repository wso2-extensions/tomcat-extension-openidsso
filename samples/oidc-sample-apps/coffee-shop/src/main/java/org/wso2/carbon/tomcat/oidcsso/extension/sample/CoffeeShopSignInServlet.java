package org.wso2.carbon.tomcat.oidcsso.extension.sample;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Servlet to indicate if a user try to sign in to a web app which is already logged in the same browser.
 *
 * @since 6.0.0
 */
public class CoffeeShopSignInServlet extends HttpServlet {
    private static final long serialVersionUID = 1640073774832490389L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)throws ServletException, IOException {
        PrintWriter out = response.getWriter();

        out.println("<HTML>");
        out.println("<HEAD>");
        out.println("<TITLE>coffee-shop</TITLE>");
        out.println("</HEAD>");
        out.println("<BODY>");
        out.print("<p>");
        out.print("Sign in to coffee-shop failed.");
        out.print("</p>");
        out.println("</BODY>");
        out.println("</HTML>");
    }
}
