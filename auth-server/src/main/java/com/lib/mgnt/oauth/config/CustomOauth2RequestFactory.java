package com.lib.mgnt.oauth.config;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;

import com.lib.mgnt.oauth.service.CustomUserDetailsService;

public class CustomOauth2RequestFactory extends DefaultOAuth2RequestFactory {
	
	@Autowired
	private TokenStore tokenStore;
	
	@Autowired
	private UserDetailsService userDetailsService;

	private static final Logger LOGGER = LoggerFactory.getLogger(CustomOauth2RequestFactory.class);

	
	public CustomOauth2RequestFactory(ClientDetailsService clientDetailsService) {
		super(clientDetailsService);
	}


	@Override
	public TokenRequest createTokenRequest(Map<String, String> requestParameters,
			ClientDetails authenticatedClient) {
		LOGGER.error("Grant_type :{}",requestParameters.get("grant_type"));
		if (requestParameters.get("grant_type").equals("refresh_token")) {
			OAuth2Authentication authentication = tokenStore.readAuthenticationForRefreshToken(
					tokenStore.readRefreshToken(requestParameters.get("refresh_token")));
			SecurityContextHolder.getContext()
					.setAuthentication(new UsernamePasswordAuthenticationToken(authentication.getName(), null,
							userDetailsService.loadUserByUsername(authentication.getName()).getAuthorities()));
		}
		return super.createTokenRequest(requestParameters, authenticatedClient);
	}
}
