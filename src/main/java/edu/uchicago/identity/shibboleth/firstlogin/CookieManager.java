package edu.uchicago.identity.shibboleth.firstlogin;

import org.springframework.web.util.CookieGenerator;
import org.springframework.webflow.execution.RequestContext;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Created by davel on 8/21/15.
 */
public class CookieManager extends CookieGenerator {

    private HttpServletRequest req;
    private HttpServletResponse resp;

    private static final String cookieName = "firstLogin";

    public CookieManager(RequestContext context) {
        super();

        req = (HttpServletRequest) context.getExternalContext().getNativeRequest();
        resp = (HttpServletResponse) context.getExternalContext().getNativeResponse();
    }

    /**
     * Adds a cookie to the browser
     * @param cookieValue
     */
    public void addCookie(final String cookieValue) {
        setCookieName(cookieName);
        Cookie cookie = createCookie(cookieValue);
        cookie.setSecure(true);
        cookie.setHttpOnly(true);

        resp.addCookie(cookie);
    }

    /**
     * Look for our cookie and return the value
     * @return the value of our cookie or null if no cookie
     */
    public String retreiveCookieValue() {
        for (Cookie c : req.getCookies()) {
            if (c.getName().equals(cookieName)) {
                return c.getValue();
            }
        }

        return null;
    }


}
