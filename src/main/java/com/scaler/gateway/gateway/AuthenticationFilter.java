package com.scaler.gateway.gateway;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter
        .Config> {

    @Autowired
    private WebClient.Builder webClientBuilder;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            // Check for Authorization header
            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            // Extract token
            String token = authHeader.substring(7);

            // Call auth server to validate token
            return webClientBuilder.build()
                    .get()
                    .uri("http://192.168.28.128:9090/api/v1/auth/validate?token=" + token)
                    .retrieve()
                    .bodyToMono(Boolean.class)
                    .flatMap(isValid -> {
                        if (Boolean.TRUE.equals(isValid)) {
                            // Token is valid, proceed to product server
                            return chain.filter(exchange);
                        } else {
                            // Token is invalid
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        }
                    })
                    .onErrorResume(e -> {
                        // Handle errors (e.g., auth server unavailable)
                        exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
                        return exchange.getResponse().setComplete();
                    });
        };
    }

    public static class Config {
        // Add configuration properties if needed (e.g., auth server URL)
    }
}