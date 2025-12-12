package com.polarbookshop.edgeservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.csrf.CsrfToken;

import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {


    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, ReactiveClientRegistrationRepository clientRegistrationRepository) {
        return http
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/", "/*.css", "/*.js", "/favicon.ico").permitAll()
                        .pathMatchers(HttpMethod.GET, "/books/**").permitAll()
                        .anyExchange().authenticated()
                )
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)))
                .oauth2Login(Customizer.withDefaults())
                .logout(logout -> logout.logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository)))
                .csrf(csrf -> csrf.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse()))
                .build();
    }

    private ServerLogoutSuccessHandler oidcLogoutSuccessHandler(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        var oidcLogoutSuccessHandler = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
        return oidcLogoutSuccessHandler;
    }

    @Bean
    WebFilter csrfWebFilter() {
        // Required because of https://github.com/spring-projects/spring-security/issues/5766
        return (exchange, chain) -> {
            exchange.getResponse().beforeCommit(() -> Mono.defer(() -> {
                Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
                return csrfToken != null ? csrfToken.then() : Mono.empty();
            }));
            return chain.filter(exchange);
        };
    }
}
/*1. Will csrfToken.then() work for beforeCommit(...)? Yes. beforeCommit expects Supplier<? extends Mono<Void>>. Inside the lambda we return either csrfToken.then() -> Mono<Void> or Mono.empty() -> Mono<Void>. Signature matches. then() returns Mono<Void> because Mono<CsrfToken> is a Mono that completes with CsrfToken; then() means “ignore value, only wait for completion”.

2. What does “wait for completion” mean? In reactive programming nothing happens until someone subscribes. When subscribed: operators run, Mono executes logic (create token, save it, write headers), then emits onComplete. In WebFlux before sending the response: response.beforeCommit(actionSupplier); then Mono<Void> m = actionSupplier.get(); m.subscribe(...); and only then does execution begin. csrfToken.then() completes only after the token is loaded/created, saved, and the Set-Cookie header is written. So “wait for completion” means: don’t send the response until the CSRF Mono finishes.

3. How is token creation and saving triggered? The config has csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse()). The CSRF filter creates Mono<CsrfToken> and stores it in exchange attributes. That Mono is lazy: if a token exists in the cookie -> load; else generate + save. CookieServerCsrfTokenRepository.saveToken writes Set-Cookie:XSRF-TOKEN=... inside that Mono. Our csrfWebFilter uses beforeCommit(() -> csrfToken.then()) forcing subscription. Subscription triggers the CSRF filter logic (generate if needed, save token, repository writes cookie). Without this filter the Mono would never run, so no cookie appears.

4. How does the client get the token? Backend: first GET triggers csrfWebFilter, which forces token Mono to run; CSRF filter + repository add Set-Cookie:XSRF-TOKEN=... Browser: receives response, sees Set-Cookie, stores cookie. Frontend (Angular): reads XSRF-TOKEN cookie and sends X-XSRF-TOKEN header on POST/PUT/DELETE. Next request: browser sends cookie automatically; Angular sends header; CSRF filter compares cookie and header; if equal -> OK; else -> invalid token.

5. Why is the custom filter needed? WebFlux is lazy. MVC immediately creates the token; WebFlux only creates a Mono. Without subscription, token is never generated and cookie is not written. The custom filter guarantees subscription before commit so Set-Cookie is sent.

6. Why return csrfToken.then() instead of csrfToken? beforeCommit expects Mono<Void>. We don’t need the CsrfToken value, only side effects. then() ignores the value and returns Mono<Void> that completes when token logic completes. If csrfToken == null return Mono.empty(), meaning do nothing. Purpose: ensure CSRF Mono runs so cookie generation happens.
*/