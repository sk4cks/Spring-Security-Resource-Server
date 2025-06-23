package spring_security.configs;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.servlet.Filter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import spring_security.filter.authentication.JwtAuthenticationFilter;
import spring_security.filter.authorization.JwtAuthorizationMacFilter;
import spring_security.filter.authorization.JwtAuthorizationRsaFilter;
import spring_security.filter.authorization.JwtAuthorizationRsaPublicKeyFilter;
import spring_security.signature.MacSecuritySigner;
import spring_security.signature.RsaPublicKeySecuritySigner;
import spring_security.signature.RsaSecuritySigner;

@Configuration
public class OAuth2ResourceServer {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable());
        http.sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(request -> request
                .requestMatchers("/").permitAll()
                .anyRequest().authenticated());
        http.userDetailsService(this.userDetailsService());
        http.addFilterBefore(this.jwtAuthenticationFilter(null, null), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(this.jwtAuthorizationRsaPublicKeyFilter(null), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public JwtAuthorizationRsaPublicKeyFilter jwtAuthorizationRsaPublicKeyFilter(JwtDecoder jwtDecoder) throws JOSEException {
        return new JwtAuthorizationRsaPublicKeyFilter(jwtDecoder);
    }

//    @Bean
//    public JwtAuthorizationRsaFilter jwtAuthorizationRsaFilter(RSAKey rsaKey) throws JOSEException {
//        return new JwtAuthorizationRsaFilter(new RSASSAVerifier(rsaKey.toRSAPublicKey()));
//    }

   /* @Bean
    public JwtAuthorizationMacFilter jwtAuthorizationMacFilter(OctetSequenceKey octetSequenceKey) throws JOSEException {
        return new JwtAuthorizationMacFilter(new MACVerifier(octetSequenceKey.toSecretKey()));
    }*/

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(RsaPublicKeySecuritySigner rsaPublicKeySecuritySigner, RSAKey rsaKey) throws Exception {
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(rsaPublicKeySecuritySigner, rsaKey);
        jwtAuthenticationFilter.setAuthenticationManager(this.authenticationManager(null));

        return jwtAuthenticationFilter;
    }
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("1234").authorities("ROLE_USER").build();

        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
