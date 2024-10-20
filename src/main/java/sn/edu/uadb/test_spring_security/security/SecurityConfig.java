package sn.edu.uadb.test_spring_security.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    private DataSource dataSource;
    private AuthEntryPoint authEntryPoint;

    @Bean
    private AuthTokenFilter authTokenFilter(){
        return new AuthTokenFilter();
    };
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) ->
                requests
                        .requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated());
        http.exceptionHandling(e->e.authenticationEntryPoint(authEntryPoint));
//        http.formLogin(withDefaults());
//        http.httpBasic(withDefaults());
        http.csrf(c->c.disable());
        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
//    @Bean
//    UserDetailsService userDetailsService(){
//        UserDetails user1= User.withUsername("thierno")
//                .password("1234")
//                .roles("USER")
//                .build();
//        UserDetails user2= User.withUsername("amadou")
//                .password("1234")
//                .roles("ADMIN")
//                .build();
//        UserDetails user3= User.withUsername("malady")
//                .password("1234")
//                .roles("ORGANISATEUR")
//                .build();
//        JdbcUserDetailsManager jdbcUserDetailsManager =new JdbcUserDetailsManager(dataSource);
//        jdbcUserDetailsManager.createUser(user1);
//        jdbcUserDetailsManager.createUser(user2);
//        jdbcUserDetailsManager.createUser(user3);
//        return jdbcUserDetailsManager;
//    }
    @Bean
    CommandLineRunner initialdata(UserDetailsService userDetailsService){
        return  args ->{
            UserDetails user1= User.withUsername("thierno")
                    .password("1234")
                    .roles("USER")
                    .build();
            UserDetails user2= User.withUsername("amadou")
                    .password("1234")
                    .roles("ADMIN")
                    .build();
            UserDetails user3= User.withUsername("malady")
                    .password("1234")
                    .roles("ORGANISATEUR")
                    .build();
            JdbcUserDetailsManager jdbcUserDetailsManager =new JdbcUserDetailsManager(dataSource);
            jdbcUserDetailsManager.createUser(user1);
            jdbcUserDetailsManager.createUser(user2);
            jdbcUserDetailsManager.createUser(user3);
        };
    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
