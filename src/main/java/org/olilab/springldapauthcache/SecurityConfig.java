package org.olilab.springldapauthcache;

import lombok.extern.slf4j.Slf4j;
import org.olilab.springldapauthcache.security.ldap.authentication.CachingLdapAuthenticationProvider;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.cache.SpringCacheBasedUserCache;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;

import java.util.Collections;

@Configuration
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().fullyAuthenticated()
                .and()
                .httpBasic()
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {

        BindAuthenticator bindAuthenticator = new BindAuthenticator(
                contextSource());
        bindAuthenticator.setUserSearch(userSearch());
        CachingLdapAuthenticationProvider ldapAuthenticationProvider = new CachingLdapAuthenticationProvider(
                bindAuthenticator, defaultLdapAuthoritiesPopulator());


        ldapAuthenticationProvider.setUserCache(new SpringCacheBasedUserCache(new ConcurrentMapCache("authenticationCache")));

        auth.authenticationProvider(ldapAuthenticationProvider);
    }

    @Bean
    public DefaultSpringSecurityContextSource contextSource() {
        return new DefaultSpringSecurityContextSource(
                Collections.singletonList("ldap://localhost:8389"), "dc=memorynotfound,dc=com");

    }

    @Bean
    public FilterBasedLdapUserSearch userSearch() {
        FilterBasedLdapUserSearch userSearch = new FilterBasedLdapUserSearch(
                "ou=people", "(uid={0})", contextSource());
        userSearch.setSearchSubtree(true);
        return userSearch;
    }

    @Bean
    public DefaultLdapAuthoritiesPopulator defaultLdapAuthoritiesPopulator() {
        log.debug("Defined default strategy for ldap authorities populator.");

        DefaultLdapAuthoritiesPopulator defaultLdapAuthoritiesPopulator = new DefaultLdapAuthoritiesPopulator(
                contextSource(), "ou=groups");
        defaultLdapAuthoritiesPopulator.setGroupSearchFilter("uniqueMember={0}");
        defaultLdapAuthoritiesPopulator
                .setGroupRoleAttribute("cn");
        defaultLdapAuthoritiesPopulator.setSearchSubtree(true);
        defaultLdapAuthoritiesPopulator
                .setIgnorePartialResultException(true);

        return defaultLdapAuthoritiesPopulator;

    }


}
