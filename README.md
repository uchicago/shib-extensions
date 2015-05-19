# Shibboleth Identity Provider Extensions
Extensions for the Shibboleth Identity Provider v3. 

## Components

### AuthnClassPredicate

A predicate used to examine the principal request context for a matching authn class. If a match is found,
it will delegate to another predicate for additional processing.

Example:
Ensure the authn class is `http://id.incommon.org/assurance/silver` and `eduPersonAssuance` 
carries `http://id.incommon.org/assurance/silver`:

```xml
<bean id="shibboleth.context-check.Condition" parent="shibboleth.Conditions.AND">
  <constructor-arg>
      <list>
          <bean class="net.shibboleth.idp.profile.logic.AuthnClassPredicate"
              c:authnClassesToMatch-ref="authnClassesToMatch"
              c:predicateToDelegate-ref="attributePredicate" />
      </list>
  </constructor-arg>
</bean>

<util:set id="authnClassesToMatch">
  <value>http://id.incommon.org/assurance/silver</value>
</util:set>

<bean id="attributePredicate" class="net.shibboleth.idp.profile.logic.SimpleAttributePredicate">
  <property name="attributeValueMap">
      <map>
          <entry key="eduPersonAssurance">
              <list>
                  <value>http://id.incommon.org/assurance/silver</value>
              </list>
          </entry>
      </map>
  </property>
</bean>
```
