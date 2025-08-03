package spring_security.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import spring_security.dto.OpaqueDto;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

@RestController
public class IndexController {


    @GetMapping("/")
    public Authentication index(Authentication authentication, @AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {

        BearerTokenAuthentication authenticationToken = (BearerTokenAuthentication) authentication;
        Map<String, Object> tokenAttributes = authenticationToken.getTokenAttributes();
        boolean active = (boolean) tokenAttributes.get("active");
        OpaqueDto opaqueDto = OpaqueDto.builder()
                .active(active)
                .authentication(authentication)
                .principal(principal)
                .build();

        return authentication;
    }

    @GetMapping("/api/user")
    public Authentication index(Authentication authentication, @AuthenticationPrincipal Jwt principal) throws URISyntaxException {
        JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) authentication;
        String sub = (String) authenticationToken.getTokenAttributes().get("sub");
        String email = (String) authenticationToken.getTokenAttributes().get("email");
        String scope = (String) authenticationToken.getTokenAttributes().get("scope");

        String sub1 = principal.getClaim("sub");
        String token = principal.getTokenValue();

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + token);
        RequestEntity<String> request = new RequestEntity<>(headers, HttpMethod.GET, new URI("http://localhost:8082"));
//        ResponseEntity<String> response = restTemplate.exchange(request, String.class);
//        String body = response.getBody();


        return authentication;
    }
}
