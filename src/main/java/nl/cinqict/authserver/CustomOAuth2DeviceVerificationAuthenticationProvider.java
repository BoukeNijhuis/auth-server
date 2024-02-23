package nl.cinqict.authserver;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceVerificationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

import java.security.Principal;
import java.util.Base64;
import java.util.Set;

public class CustomOAuth2DeviceVerificationAuthenticationProvider implements AuthenticationProvider {

    static final OAuth2TokenType USER_CODE_TOKEN_TYPE = new OAuth2TokenType("user_code");
    private static final StringKeyGenerator DEFAULT_STATE_GENERATOR = new Base64StringKeyGenerator(Base64.getUrlEncoder());
    private final Log logger = LogFactory.getLog(this.getClass());
    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService authorizationService;

    public CustomOAuth2DeviceVerificationAuthenticationProvider(RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationService = authorizationService;
    }
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2DeviceVerificationAuthenticationToken deviceVerificationAuthentication = (OAuth2DeviceVerificationAuthenticationToken)authentication;
        OAuth2Authorization authorization = this.authorizationService.findByToken(deviceVerificationAuthentication.getUserCode(), USER_CODE_TOKEN_TYPE);
        if (authorization == null) {
            throw new OAuth2AuthenticationException("invalid_grant");
        } else {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Retrieved authorization with user code");
            }

            Authentication principal = (Authentication)deviceVerificationAuthentication.getPrincipal();
//            if (!isPrincipalAuthenticated(principal)) {
//                if (this.logger.isTraceEnabled()) {
//                    this.logger.trace("Did not authenticate device verification request since principal not authenticated");
//                }
//
//                return deviceVerificationAuthentication;
//            } else {
                RegisteredClient registeredClient = this.registeredClientRepository.findById(authorization.getRegisteredClientId());
                if (this.logger.isTraceEnabled()) {
                    this.logger.trace("Retrieved registered client");
                }

                Set<String> requestedScopes = (Set)authorization.getAttribute("scope");
//                OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(registeredClient.getId(), principal.getName());
//                if (requiresAuthorizationConsent(requestedScopes, currentAuthorizationConsent)) {
//                    String state = DEFAULT_STATE_GENERATOR.generateKey();
//                    authorization = OAuth2Authorization.from(authorization).principalName(principal.getName()).attribute(Principal.class.getName(), principal).attribute("state", state).build();
//                    if (this.logger.isTraceEnabled()) {
//                        this.logger.trace("Generated device authorization consent state");
//                    }
//
//                    this.authorizationService.save(authorization);
//                    if (this.logger.isTraceEnabled()) {
//                        this.logger.trace("Saved authorization");
//                    }
//
//                    Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null ? currentAuthorizationConsent.getScopes() : null;
//                    AuthorizationServerSettings authorizationServerSettings = AuthorizationServerContextHolder.getContext().getAuthorizationServerSettings();
//                    String deviceVerificationUri = authorizationServerSettings.getDeviceVerificationEndpoint();
//                    return new OAuth2DeviceAuthorizationConsentAuthenticationToken(deviceVerificationUri, registeredClient.getClientId(), principal, deviceVerificationAuthentication.getUserCode(), state, requestedScopes, currentAuthorizedScopes);
//                } else {
                    OAuth2Authorization.Token<OAuth2UserCode> userCode = authorization.getToken(OAuth2UserCode.class);
                    authorization = OAuth2Authorization.from(authorization).principalName(principal.getName()).authorizedScopes(requestedScopes).token((OAuth2UserCode)userCode.getToken(), (metadata) -> {
                        metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true);
                    }).attribute(Principal.class.getName(), principal).attributes((attributes) -> {
                        attributes.remove("scope");
                    }).build();
                    this.authorizationService.save(authorization);
                    if (this.logger.isTraceEnabled()) {
                        this.logger.trace("Saved authorization with authorized scopes");
                        this.logger.trace("Authenticated device verification request");
                    }

                    return new OAuth2DeviceVerificationAuthenticationToken(principal, deviceVerificationAuthentication.getUserCode(), registeredClient.getClientId());
//                }
//            }
        }
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2DeviceVerificationAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static boolean requiresAuthorizationConsent(Set<String> requestedScopes, OAuth2AuthorizationConsent authorizationConsent) {
        return authorizationConsent == null || !authorizationConsent.getScopes().containsAll(requestedScopes);
    }

    private static boolean isPrincipalAuthenticated(Authentication principal) {
        return principal != null && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass()) && principal.isAuthenticated();
    }
}
