package com.luv2code.springboot.cruddemo.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class SecurityConfig {

    //configure jdbc support
    @Bean
    public UserDetailsManager userDetailsManager(DataSource dataSource){
        //inject datasource - autoconfigured
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);

        //providing custom queries to find user and authorities with custom table names
        userDetailsManager.setUsersByUsernameQuery("select user_id, pw, active from members where user_id=?");
        userDetailsManager.setAuthoritiesByUsernameQuery("select user_id, role from roles where user_id=?");

        return userDetailsManager;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        http.authorizeHttpRequests(config ->
            config
                    .requestMatchers(HttpMethod.GET,"/api/employees").hasRole("EMPLOYEE")
                    .requestMatchers(HttpMethod.GET,"/api/employees/**").hasRole("EMPLOYEE")
                    .requestMatchers(HttpMethod.POST,"api/employees").hasRole("MANAGER")
                    .requestMatchers(HttpMethod.PUT,"api/employees").hasRole("MANAGER")
                    .requestMatchers(HttpMethod.DELETE,"api/employees/**").hasRole("ADMIN"));

        //basic http authentication
        http.httpBasic(Customizer.withDefaults());

        http.csrf(csrf -> csrf.disable());

        return http.build();
    }



    /**
     @Bean
     public InMemoryUserDetailsManager userDetailsManager(){

     UserDetails john = User.builder()
     .username("john")
     .password("{noop}test123")
     .roles("EMPLOYEE")
     .build();

     UserDetails mary = User.builder()
     .username("mary")
     .password("{noop}test123")
     .roles("EMPLOYEE","MANAGER")
     .build();

     UserDetails susan = User.builder()
     .username("susan")
     .password("{noop}test123")
     .roles("EMPLOYEE","MANAGER","ADMIN")
     .build();

     return new InMemoryUserDetailsManager(john,mary,susan);
     }
     **/
}
