package willydekeyser.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Autowired
	private  AuthHandler authenticationSuccessHandler;

	@Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
		.authorizeHttpRequests((authorize) -> authorize
			.requestMatchers("/css/**", "/favicon.ico", "/", "/index").permitAll()
			.requestMatchers("/public-data").hasAnyRole("USER", "ADMIN")
			.requestMatchers("/private-data").hasRole("ADMIN")
			.anyRequest().authenticated()
		)
		.formLogin(login -> login
				.loginPage("/login")
				.successHandler(authenticationSuccessHandler)
				.permitAll())
		.logout(logout -> logout
				.logoutSuccessUrl("/"))
				.csrf().disable();
        return http.build();
    }
	
	@Bean
	PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
	
	@Bean
	UserDetailsManager inMemoryUserDetailsManager() {
		var user = User.withUsername("user").password("{noop}password").roles("USER").build();
		var admin = User.withUsername("admin").password("{noop}password").roles("USER", "ADMIN").build();
		return new InMemoryUserDetailsManager(user, admin);
	}
}
