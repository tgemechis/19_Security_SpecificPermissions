package com.meklit.demo;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity

public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

        //Using the bean for the password encoder, instead of putting it in the configure method.
        //The bean is always available in the context path once the application is run.
    @Bean
    PasswordEncoder passwordEncoder()
    {

        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/")
               .access("hasAuthority('USER') or hasAuthority('ADMIN')")
                .antMatchers("/admin").access("hasAuthority('ADMIN')")
                .anyRequest().authenticated()
                .and()
                .formLogin().loginPage("/login").permitAll()
                .and()
                .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"));



    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //Set up in memory authentication. REMOVE THIS for production deployments
        PasswordEncoder e =  passwordEncoder();
        auth.inMemoryAuthentication()
                .withUser("user").password(passwordEncoder().encode("password")).authorities("USER")
                .and()
                .withUser("admin").password(passwordEncoder().encode("password")).authorities("ADMIN")
                .and()
                .passwordEncoder(passwordEncoder()).passwordEncoder(e);

        //Get user details from the SS User Details Service for the user who is trying to log in.
      //  auth.userDetailsService(userDetailsServiceBean()).passwordEncoder(passwordEncoder());

    }
}