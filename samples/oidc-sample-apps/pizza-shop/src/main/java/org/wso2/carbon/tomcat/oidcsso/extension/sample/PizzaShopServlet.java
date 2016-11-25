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
 * This is a sample java Servlet class to show the responses of OpenId Connect flow of the web app
 */
public class PizzaShopServlet extends HttpServlet {
    private static final long serialVersionUID = -8541360610239439894L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {


        OIDCLoggedInSession object = (OIDCLoggedInSession) request.getSession(false)
                .getAttribute(Constants.SESSION_BEAN);
        String authenticationErrorResponse = (String) request.getSession(false)
                .getAttribute(Constants.ERROR_AUTHENTICATION_RESPONSE);
        String failedAuthenticationResponseValidation = (String) request.getSession(false)
                .getAttribute(Constants.AUTHENTICATION_RESPONSE_VALIDATION_FAILED);
        String failedTokenResponseValidation = (String) request.getSession(false)
                .getAttribute(Constants.TOKEN_RESPONSE_VALIDATION_FAILED);
        String tokenErrorResponse = (String) request.getSession(false).getAttribute(Constants.ERROR_TOKEN_RESPONSE);
        String userInfoErrorResponse = (String) request.getSession(false)
                .getAttribute(Constants.ERROR_USER_INFO_RESPONSE);
        String userInfoSuccessResponse = (String) request.getSession(false).getAttribute(Constants.USER_INFO_RESPONSE);


        PrintWriter out = response.getWriter();


        out.println("<HTML>");
        out.println("<HEAD>");
        out.println("<TITLE>pizza-shop</TITLE>");
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
        if (failedAuthenticationResponseValidation != null) {
            out.print(failedAuthenticationResponseValidation + "<br />");
        }
        if (authenticationErrorResponse != null) {
            out.print("Authentication Error Response. <br />");
            out.print("<br />");
            out.print("Error : " + authenticationErrorResponse);
        }
        if (failedTokenResponseValidation != null) {
            out.print(failedTokenResponseValidation + "<br />");
        }
        if (tokenErrorResponse != null) {
            out.print("Token Error Response. <br />");
            out.print("<br />");
            out.print("Error : " + tokenErrorResponse);
        }
        if (userInfoErrorResponse != null) {
            out.print("User Info Error Response. <br />");
            out.print("<br />");
            out.print("Error : " + userInfoErrorResponse);
        }
        if (userInfoSuccessResponse != null) {
            out.print("User Info : " + userInfoSuccessResponse + "<br />");
            out.print("<br />");
        }

        out.print("</p>");
        out.print("<p>");
        out.print("<a href=\"http://localhost:8080/pizza-shop/logout\">Logout</a>\n");
        out.print("</p>");
        out.print("<iframe id=\"rpIFrame\" src=\"rpiFrame.jsp\" frameborder=\"0\" width=\"0\" height=\"0\"></iframe>");
        out.println("</BODY>");
        out.println("</HTML>");
    }
}
