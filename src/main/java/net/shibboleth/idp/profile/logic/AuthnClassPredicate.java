package net.shibboleth.idp.profile.logic;

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.RequestedPrincipalContext;
import org.opensaml.profile.context.ProfileRequestContext;
import com.google.common.base.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.util.Arrays;
import java.util.Set;

/**
 * @author Misagh Moayyed
 */
public final class AuthnClassPredicate implements Predicate<ProfileRequestContext> {
    private final Logger log = LoggerFactory.getLogger(AuthnClassPredicate.class);

    private Set<String> authnClassesToMatch;

    private Set<String> authnClassesToForgive;

    private Predicate<ProfileRequestContext> predicateToDelegate;

    public AuthnClassPredicate(Set<String> authnClassesToMatch,
                               Set<String> authnClassesToForgive,
                               Predicate<ProfileRequestContext> predicateToDelegate) {
        this.authnClassesToMatch = authnClassesToMatch;
        this.predicateToDelegate = predicateToDelegate;
        this.authnClassesToForgive = authnClassesToForgive;
    }

    @Override
    public boolean apply(ProfileRequestContext profileRequestContext) {
        log.debug("Evaluating profile request context for authn class...");

        log.debug("Getting authn context from the profile request context...");
        final AuthenticationContext authnContext = profileRequestContext.getSubcontext(AuthenticationContext.class);

        log.debug("Getting requested principal from the authn context...");
        final RequestedPrincipalContext principalContext = authnContext.getSubcontext(RequestedPrincipalContext.class);

        if (principalContext == null) {
            log.debug("No principal context was requested. Predicate wil ignore the context");
            return true;
        }

        log.debug("Getting matching principal from the principal context...");
        final Principal principal = principalContext.getMatchingPrincipal();
        final String principalName = principal.getName();
        log.debug("Matching principal name is {}", principalName);

        if (this.authnClassesToForgive.contains(principalName)) {
            log.debug("The requested authn principal {} is forgiven by the set of {}. Predicate wil ignore the context",
                    principalName, Arrays.toString(this.authnClassesToMatch.toArray()));
            return true;
        }

        if (this.authnClassesToMatch.contains(principalName)) {
            log.debug("Found matching principal name {} for the requested authn class. Calling delegate...",
                    principalName);

            boolean delegateResult = this.predicateToDelegate.apply(profileRequestContext);
            if (delegateResult) {
                log.debug("Delegate {} returned true. Moving on...", this.predicateToDelegate.getClass().getSimpleName());
                return true;
            }

            log.debug("Delegate could not evaluate the context. Failing...");
            return false;

        }
        log.warn("Could not match the requested authn principal {} against {}",
                principalName, Arrays.toString(this.authnClassesToMatch.toArray()));
        return false;
    }


}
