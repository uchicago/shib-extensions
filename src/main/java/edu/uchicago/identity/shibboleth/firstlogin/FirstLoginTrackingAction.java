package edu.uchicago.identity.shibboleth.firstlogin;

import org.springframework.webflow.execution.RequestContext;

/**
 * Created by davel on 8/21/15.
 */
public class FirstLoginTrackingAction {

    public FirstLoginTrackingAction(){
        super();
    }

    /**
     * Determine if we are running through the login flow the first time or not.
     * @param context
     * @return
     */
    public Boolean isFirstTime(RequestContext context) {

        CookieManager cm = new CookieManager(context);
        if(cm.retreiveCookieValue() != null) {
            return false;
        }
        else {
            cm.addCookie("first");
            return true;
        }
    }
}
