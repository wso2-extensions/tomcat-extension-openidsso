<%--
 Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.

 WSO2 Inc. licenses this file to you under the Apache License,
 Version 2.0 (the "License"); you may not use this file except
 in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied. See the License for the
 specific language governing permissions and limitations
 under the License.
--%>

<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.wso2.carbon.tomcat.oidcsso.extension.Constants" %>

<html>
<head>
<title>OpenID Connect Session Management RP IFrame</title>
    <script language="JavaScript" type="text/javascript">
    var stat = "unchanged";
    var client_id = "<%=session.getAttribute(Constants.CLIENT_ID)%>";
    var session_state = '<%=session.getAttribute(Constants.SESSION_STATE)%>';
    var mes = client_id + " " + session_state;
    var targetOrigin = "https://localhost:9443/oidc/checksession?client_id=<%=session.getAttribute(Constants.CLIENT_ID)%>";

    function check_session() {
        if (client_id !== null && client_id.length != 0 && client_id !== 'null' && session_state !== null &&
                        session_state.length != 0 && session_state != 'null') {
            var win = document.getElementById("opIFrame").contentWindow;
            win.postMessage(mes, targetOrigin);
        }
    }

    function setTimer() {
        check_session();
        setInterval("check_session()", 3 * 1000);
    }

    window.addEventListener("message", receiveMessage, false);

    function receiveMessage(e) {
        if (targetOrigin.indexOf(e.origin) < 0) {
                    return;
        }
        if (e.data == "changed") {
            console.log("[RP] session state has changed. sending passive request");
            window.top.location.href = 'http://localhost:8080/coffee-shop/re-authenticate';
        }else if (e.data == "unchanged") {
            console.log("[RP] session state has not changed");
        }else {
            console.log("[RP] error while checking session status");
        }
    }
    </script>
</head>
<body onload="setTimer()">
<iframe id="opIFrame"
        src="https://localhost:9443/oidc/checksession?client_id=<%=session.getAttribute(Constants.CLIENT_ID)%>"
        frameborder="0" width="0"
        height="0"></iframe>
</body>
</html>
