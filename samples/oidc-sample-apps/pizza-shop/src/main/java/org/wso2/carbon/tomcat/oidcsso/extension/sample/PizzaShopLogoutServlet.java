package org.wso2.carbon.tomcat.oidcsso.extension.sample;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Sample java servlet to show if the user try to logout from already logged out web app.
 */
public class PizzaShopLogoutServlet extends HttpServlet {
    private static final long serialVersionUID = -7137737652718571683L;
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        PrintWriter out = response.getWriter();

        out.println("<HTML>");
        out.println("<HEAD>");
        out.println("<TITLE>pizza-shop</TITLE>");
        out.println("</HEAD>");
        out.println("<BODY>");
        out.print("<p>");
        out.print("Log out from pizza-shop failed.");
        out.print("</p>");
        out.println("</BODY>");
        out.println("</HTML>");
    }
}
