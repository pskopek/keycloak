/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.services.util;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.keycloak.common.util.Resteasy;
import org.keycloak.common.util.ServerCookie;
import org.keycloak.services.managers.AuthenticationManager;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;

import static org.keycloak.common.util.ServerCookie.SAME_SITE;


/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class CookieHelper {

    public static final String LEGACY_COOKIE = "_LEGACY";

    private static final Logger logger = Logger.getLogger(CookieHelper.class);

    /**
     * Set a response cookie.  This solely exists because JAX-RS 1.1 does not support setting HttpOnly cookies
     *  @param name
     * @param value
     * @param path
     * @param domain
     * @param comment
     * @param maxAge
     * @param secure
     * @param httpOnly
     * @param sameSite
     */
    public static void addCookie(String name, String value, String path, String domain, String comment, int maxAge, boolean secure, boolean httpOnly, SAME_SITE sameSite) {
        if (sameSite == SAME_SITE.NONE && !secure) {
            throw new IllegalArgumentException("The cookie need to have Secure attribute when using SameSite=None");
        }

        HttpResponse response = Resteasy.getContextData(HttpResponse.class);
        StringBuffer cookieBuf = new StringBuffer();
        ServerCookie.appendCookieValue(cookieBuf, 1, name, value, path, domain, comment, maxAge, secure, httpOnly, sameSite);
        String cookie = cookieBuf.toString();
        response.getOutputHeaders().add(HttpHeaders.SET_COOKIE, cookie);

        // a workaround for browser in older Apple OSs – browsers ignore cookies with SameSite=None
        if (sameSite == SAME_SITE.NONE) {
            addCookie(name + LEGACY_COOKIE, value, path, domain, comment, maxAge, secure, httpOnly, null);
        }
    }


    public static Set<String> getCookieValue(String name) {
        HttpHeaders headers = Resteasy.getContextData(HttpHeaders.class);

        Set<String> cookiesVal = new HashSet<>();

        // check for cookies in the request headers
        List<String> cookieHeader = headers.getRequestHeaders().get(HttpHeaders.COOKIE);
        if (cookieHeader != null) {
            logger.debugv("{1} cookie found in the request's header", name);
            cookieHeader.stream().map(s -> parseCookie(s, name)).forEach(cookiesVal::addAll);
        }

        // get cookies from the cookie field
        Cookie cookie = headers.getCookies().get(name);
        if (cookie != null) {
            logger.debugv("{1} cookie found in the cookie's field", name);
            cookiesVal.add(cookie.getValue());
        }


        return cookiesVal;
    }


    public static Set<String> parseCookie(String cookieHeader, String name) {
        String parts[] = cookieHeader.split("[;,]");

        Set<String> cookies = Arrays.stream(parts).filter(part -> part.startsWith(name + "=")).map(part ->
                part.substring(part.indexOf('=') + 1)).collect(Collectors.toSet());

        return cookies;
    }

    public static Cookie getCookie(Map<String, Cookie> cookies, String name) {
        Cookie cookie = cookies.get(AuthenticationManager.KEYCLOAK_SESSION_COOKIE);
        if (cookie != null) {
            return cookie;
        }
        else {
            String legacy = AuthenticationManager.KEYCLOAK_SESSION_COOKIE + LEGACY_COOKIE;
            logger.debugv("Couldn't find cookie {0}, trying {0}",
                    AuthenticationManager.KEYCLOAK_SESSION_COOKIE, legacy);
            return cookies.get(legacy);
        }
    }
}
