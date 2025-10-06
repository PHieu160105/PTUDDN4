package com.example.springbootoauth.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class TokenController {

    private final OAuth2AuthorizedClientService authorizedClientService;
    private final OAuth2AuthorizedClientManager authorizedClientManager;

    public TokenController(OAuth2AuthorizedClientService authorizedClientService,
                           OAuth2AuthorizedClientManager authorizedClientManager) {
        this.authorizedClientService = authorizedClientService;
        this.authorizedClientManager = authorizedClientManager;
    }

    @GetMapping("/api/tokens")
    public Map<String, Object> tokens(@AuthenticationPrincipal OidcUser oidcUser) {
        Map<String, Object> response = new HashMap<>();

        if (oidcUser == null) {
            response.put("message", "Not logged in");
            return response;
        }

        String principalName = oidcUser.getName();
        OAuth2AuthorizedClient client =
                authorizedClientService.loadAuthorizedClient("auth0", principalName);

        if (client == null) {
            response.put("message", "No authorized client found");
            return response;
        }

        response.put("principal", principalName);
        response.put("access_token_expires_at", client.getAccessToken().getExpiresAt());
        response.put("has_refresh_token", client.getRefreshToken() != null);

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("auth0")
                .principal(principalName)
                .build();

        OAuth2AuthorizedClient refreshed = authorizedClientManager.authorize(authorizeRequest);
        if (refreshed != null) {
            response.put("refreshed_access_token", refreshed.getAccessToken().getTokenValue());
        } else {
            response.put("refreshed_access_token", "null");
        }

        return response;
    }
}
