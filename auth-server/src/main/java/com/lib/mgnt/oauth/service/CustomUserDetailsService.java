package com.lib.mgnt.oauth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import com.lib.mgnt.oauth.dao.UserDao;
import com.lib.mgnt.oauth.entity.UserInfo;
import com.lib.mgnt.oauth.enums.UserStatus;

@Service
public class CustomUserDetailsService implements UserDetailsService {

	private static final Logger LOGGER = LoggerFactory.getLogger(CustomUserDetailsService.class);
	
	@Autowired
	private UserDao userDao;

	@Override
	public UserDetails loadUserByUsername(String input) {
		UserInfo user = userDao.findByEmailAndUserStatus(input,UserStatus.ACTIVE);
		LOGGER.error("User data");
		if (user == null)
			throw new BadCredentialsException("Bad credentials");

		new AccountStatusUserDetailsChecker().check(user);

		return user;
	}
}
