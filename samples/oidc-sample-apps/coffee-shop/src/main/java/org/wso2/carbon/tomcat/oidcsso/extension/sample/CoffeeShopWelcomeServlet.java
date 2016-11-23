package org.wso2.carbon.tomcat.oidcsso.extension.sample;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Welcome servlet of a sample web app which redirects to signin to the web app.
 *
 * @since 6.0.0
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
