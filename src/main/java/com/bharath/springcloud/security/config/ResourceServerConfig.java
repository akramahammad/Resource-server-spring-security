package com.bharath.springcloud.security.config;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;



@EnableWebSecurity
public class ResourceServerConfig {
	
	@Bean
	public SecurityFilterChain resourceFilterChain(HttpSecurity http) throws Exception {
		
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtToRolesConverter());
		
		http.authorizeRequests(authorizeRequest -> {
			authorizeRequest.mvcMatchers(HttpMethod.GET, "/couponapi/coupons/{code:^[A-Z]*$}")
			.hasAnyRole("admin","user").mvcMatchers(HttpMethod.POST,"/couponapi/coupons")
			.hasAnyRole("admin");
			}).oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter);
		
		return http.build();
	}
	
	@Bean
	public Converter<Jwt,Collection<GrantedAuthority>> jwtToRolesConverter(){
		
		return new Converter<Jwt, Collection<GrantedAuthority>>() {

			@Override
			public Collection<GrantedAuthority> convert(Jwt jwt) {
				// TODO Auto-generated method stub
				List<String> roles = jwt.getClaimAsStringList("roles");
				if(roles!=null) {
					return roles.stream().map(eachRole -> new SimpleGrantedAuthority(eachRole))
					.collect(Collectors.toList());
				}
				return Collections.emptyList();
			}
		};
	}
	

}
