package com.lib.mgnt.oauth.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.lib.mgnt.oauth.entity.UserInfo;
import com.lib.mgnt.oauth.enums.UserStatus;

public interface UserDao extends JpaRepository<UserInfo, Integer> {

	UserInfo findByUsername(String username);
	
	UserInfo findByUsernameAndUserStatus(String username, UserStatus active);
	
	UserInfo findByEmail(String email);
	
	UserInfo findByEmailAndUserStatus(String email, UserStatus active);


}
