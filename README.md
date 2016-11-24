# tomcat-extension-openidsso #

 OpenID Connect (OIDC) is an identity layer protocol on top of OAuth 2.0.
 This extension provides the capability of enabling SSO and SLO using OIDC for user applications via WSO2 Identity Server.

 Follow the below steps to see how this extension works.

 We will use two web applications named ‘pizza-shop’ and ‘coffee-shop’  with WSO2 Identity server.

## Step 1: Download and install Tomcat 8 and WSO2 IS. ##

 Tomcat 8 will be used to deploy web applications and WSO2 IS will be used as the identity provider that enables SSO and SLO.

   1. Download Tomcat 8 and extract the zip file to your computer. 
        The extracted directory will be your <Tomcat_HOME> directory.
   2. Download WSO2 IS and extract the zip file to your computer. 
        The extracted directory will be your <IS_HOME> directory.

## Step 2: Checkout the project. ##

Checkout the project using below command

    git clone https://github.com/Abilashini/tomcat-extension-openidsso.git

## Step 3: Register web applications on WSO2 Identity Server. ##

 Here WSO2 Identity Server will act as the identity provider for service providers.
 We have to register web apps as service providers to give them the single sign on capability.
 Follow the below steps to register coffee-shop app and pizza-shop applications as service providers.

 1. Log into the management console of WSO2 IS.
 2. Click ‘Service Providers -> Add’ in the navigator.
 3. Enter 'coffee-shop' in the Service Provider Name field in the Add New Service Provider screen.

![alt tag](https://github.com/Abilashini/tomcat-extension-openidsso/blob/master/resources/Service-provider-register-1.png)
    
 4. Click Register to open the Service Providers screen.
 5. Click ‘Inbound Authentication Configuration ->  OAuth/OpenID Connect Configuration’ and click ‘Configure’.
    
![alt tag](https://github.com/Abilashini/tomcat-extension-openidsso/blob/master/resources/Service-provider-register-2.png)
    
 6. You can now start specifying the OIDC related configurations for the service provider.

	enter http://localhost:8080/coffee-shop/openid under Callback Url.
        
![alt tag](https://github.com/Abilashini/tomcat-extension-openidsso/blob/master/resources/Service-provider-register-3.png)

 7. You will receive a client key and a client secret.
    
![alt tag](https://github.com/Abilashini/tomcat-extension-openidsso/blob/master/resources/Service-provider-register-4.png)
    
 8. Open the <project_root>/samples/oidc-sample-apps/coffee-shop/src/main/webapp/META-INF/oidc-config.xml
 
	* add client key under ‘client-id’ tag
	* add client secret under ‘client-secret’ tag
 9. Repeat the above steps to register a service provider for the pizza-shop application. Use the following values:
 
	* Service Provider Name - pizza-shop
	* Callback Url - http://localhost:8080/pizza-shop/openid
	* Add the client key and client secret to the oidc-config.xml file in the <project_root>/samples/oidc-sample-apps/pizza-shop/src/main/webapp/META-INF directory.






