# Tomcat Extension - OpenID Connect based Single Sign On and Single Logout #

 OpenID Connect (OIDC) is an identity layer protocol on top of OAuth 2.0.
 This extension provides the capability of enabling SSO and SLO using OIDC for user applications via WSO2 Identity Server.

 Follow the below steps to see how this extension works.

 We will use two web applications named ‘pizza-shop’ and ‘coffee-shop’  with WSO2 Identity server.

## Step 1: Download and install Tomcat 8 and WSO2 IS ##

 Tomcat 8 will be used to deploy web applications and WSO2 IS will be used as the identity provider that enables SSO and SLO.

1. Download Tomcat 8 and extract the zip file to your computer. 
   The extracted directory will be your &lt;Tomcat_HOME&gt; directory.
2. Download WSO2 IS and extract the zip file to your computer. 
   The extracted directory will be your &lt;IS_HOME&gt; directory.

## Step 2: Checkout the project ##

Checkout the project using the below command

    git clone https://github.com/Abilashini/tomcat-extension-openidsso.git

## Step 3: Register web applications on WSO2 Identity Server ##

 Here WSO2 Identity Server will act as the identity provider for service providers.
 We have to register web apps as service providers to give them the single sign on capability.
 Follow the below steps to register coffee-shop app and pizza-shop applications as service providers.

 1. Start the WSO2 IS using the below command in the bin directory
        ./wso2server.sh run
 2. Log into the management console of WSO2 IS by accessing <https://localhost:9443/carbon/>
 3. Click ‘Service Providers -> Add’ in the navigator.
 4. Enter 'coffee-shop' in the Service Provider Name field in the Add New Service Provider screen.

 ![alt tag](https://github.com/Abilashini/tomcat-extension-openidsso/blob/master/resources/Service-provider-register-1.png)

 5. Click Register to open the Service Providers screen.

 6. Click ‘Inbound Authentication Configuration ->  OAuth/OpenID Connect Configuration’ and click ‘Configure’.

 ![alt tag](https://github.com/Abilashini/tomcat-extension-openidsso/blob/master/resources/Service-provider-register-2.png)

 7. You can now start specifying the OIDC related configurations for the service provider.

	enter http://localhost:8080/coffee-shop/openid under Callback Url.
        
 ![alt tag](https://github.com/Abilashini/tomcat-extension-openidsso/blob/master/resources/Service-provider-register-3.png)

 8. You will receive a client key and a client secret.
    
 ![alt tag](https://github.com/Abilashini/tomcat-extension-openidsso/blob/master/resources/Service-provider-register-4.png) 

 9. Open the &lt;project_root&gt;/samples/oidc-sample-apps/coffee-shop/src/main/webapp/META-INF/oidc-config.xml
 
	* add client key under ‘client-id’ tag
	* add client secret under ‘client-secret’ tag
 10. Repeat the above steps to register a service provider for the pizza-shop application. Use the following values:
 
	* Service Provider Name - pizza-shop
	* Callback Url - http://localhost:8080/pizza-shop/openid
	* Add the client key and client secret to the oidc-config.xml file in the &lt;project_root&gt;/samples/oidc-sample-apps/pizza-shop/src/main/webapp/META-INF directory.
	
## Step 4: Build the project ‘tomcat-extension-openidsso’ ##

 Build it using maven

	mvn clean install
	
## Step 5: Add the necessary configurations and libraries ##

1. Open the sever.xml file (stored in the &lt;Tomcat_HOME&gt;/conf directory).
2. Add the following under the Service tag:
        `<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
                   maxThreads="150" SSLEnabled="true" scheme="https" secure="true"
                   clientAuth="false" sslProtocol="TLS" keystoreFile="conf/wso2/wso2carbon.jks"
                   keystorePass="wso2carbon"/>`
3. Add the following under the localhost container:
`<Valve className= "org.wso2.carbon.tomcat.oidcsso.extension.oidc.OIDCSSOValve"/>`	
4. Open the context.xml file (stored in the &lt;Tomcat_HOME&gt;/conf directory).
5. Add the following under the Context tag:
`<Listener className="org.wso2.carbon.tomcat.oidcsso.extension.utils.OIDCConfigurationLoader"/>`
6. Copy the &lt;project_root&gt;/modules/oidcsso/src/main/resources/wso2 folder to &lt;Tomcat_HOME&gt;/conf
7. copy the &lt;project_root&gt;/modules/oidcsso/target/oidcsso-1.0.0-SNAPSHOT-fat.jar to <Tomcat_HOME>/lib
8. Copy the &lt;project_root&gt;/samples/oidc-sample-apps/coffee-shop/target/coffee-shop.war and &lt;project_root&gt;/samples/oidc-sample-apps/pizza-shop/target/pizza-shop.war to &lt;Tomcat_HOME&gt;/webapps folder.

## Step 6: Try out the samples ##

Start the tomcat server.

 1. Try accessing <http://localhost:8080/coffee-shop/>

 ![alt tag](https://github.com/Abilashini/tomcat-extension-openidsso/blob/master/resources/home-page.png)

 2. Click on ‘Sign In’.

 3. You will be re-directed to the Identity Server login page.

 ![alt tag](https://github.com/Abilashini/tomcat-extension-openidsso/blob/master/resources/IS-login.png)

 4. Login with your user credentials and click on ‘SIGN IN’.

 5. Click Approve Always at the consent page.

 6. Now you can see the received values of token response.

 7. Now access to <http://localhost:8080/pizza-shop/>

 8. Click on ‘Logout’ in the pizza-shop app. It will redirect to Identity Server. 

 ![alt tag](https://github.com/Abilashini/tomcat-extension-openidsso/blob/master/resources/IS-logout.png)

 9. Click on yes. 

 10. Go back to browser window of the coffee-shop app. You will see that the home page has been loaded which means coffee-shop app has been logged out. 

## Things to be consider when developing web applications ##

 1. Create a file named oidc-config.xml inside &lt;webapp_root&gt;/src/main/webapp/META-INF

 2. Format of the xml file should be as below

 ```
 <oidc-config xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://wso2.org/2016/oidc-config"
                 xsi:schemaLocation="http://wso2.org/2016/oidc-config http://wso2.org/2016/oidc-config.xsd">
        <enable>true</enable>
        <client-id></client-id>
        <client-secret></client-secret>
        <redirect-uri></redirect-uri>
        <scope>openid</scope>
        <claims></claims>
        <authentication-endpoint></authentication-endpoint>
        <token-endpoint></token-endpoint>
        <user-info-endpoint></user-info-endpoint>
        <logout-endpoint></logout-endpoint>
        <trust-store>
            <location></location>
            <type></type>
            <key-alias></key-alias>
            <password></password>
        </trust-store>
</oidc-config>
```

    * enable : 'true'
    * client-id : received from the OpenID Connect Provider (as you received when you register the service provider in the sample).
    * client-secret : received from the OIDC Provider.
    * redirect-uri : in the format of http://localhost:8080/&lt;webapp_name&gt;/openid.
    * scope : a comma-seperated string which starts with 'openid'.
        eg. openid,profile,email
    * claims : a comma-seperated string.
        eg. name,given_name,family_name
    * authentication-endpoint : the authentication endpoint URI at the OIDC Provider.
    * token-endpoint : the token endpoint URI at the OIDC Provider.
    * user-info-endpoint : the user info endpoint URI at the OIDC Provider.
    * logout-endpoint : the user logout endpoint URI at the OIDC Provider.
    * trust-store :
        * location : location of the trust store file. Make sure you have the file in the specified location.
        * type : type of the trust store file
        * key-alias : alias of the trust store
        * password : password of the trustore

    hint - if you are using WSO2 IS as your OpenID Provider then you do not need to configure the values for authentication-endpoint, token-endpoint, user-info-endpoint, logout-endpoint and trust-store.
            those values has been already specified in the server level oidc-config.xml file.

 3. Add the rpiFrame.jsp file into the &lt;webapp_root&gt;/src/main/webapp directory which can be copied from one of the sample app.

 4. Change the web app name in the below line of rpiFrame.jsp

 ``` window.top.location.href = 'http://localhost:8080/<webapp_name>/re-authenticate'; ```

 5. Start the OIDC flow by accessing the web-app with the suffix of '/signin'

        eg. http://localhost:8080/<webapp_name>/signin
