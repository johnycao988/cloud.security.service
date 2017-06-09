package com.cly.security.service.impl;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Properties;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;

import com.cly.comm.util.IDUtil;
import com.cly.ldap.LDAPContext;
import com.cly.ldap.LDAPSearch; 
import com.cly.security.SecurityAuthException;
import com.cly.security.UserInfo;
import com.cly.security.UserInfoService;

public class LDAPUserInfoService implements UserInfoService {

	private String ldapUserinfoSearchbase;
	private String ldapUserName;

	private String ldapUserGrpId;
	private String ldapUserGrpUserId;
	private String ldapUserGrpSearchbase;
	private String ldapUserId;

 	private LDAPContext ldapCtx;

	@Override
	public UserInfo login(String userId, String userPwd) throws SecurityAuthException {

		try {

	    	LDAPSearch ldapSearch = this.getLDAPSearch(userId, userPwd);
			
			Attributes atr = ldapSearch.search(ldapUserinfoSearchbase, ldapUserId + "=" + userId,
					SearchControls.SUBTREE_SCOPE); 
		 
			String slUserName = atr.get(this.ldapUserName).get().toString();
 
			UserInfoImpl ui = new UserInfoImpl();
			ui.setUserId(userId);
			ui.setUserPassword(userPwd);
			ui.setUserName(slUserName);
			ui.setAuthCode(IDUtil.getRandomBase64UUID());
			ui.setUserGroups(this.getUserGroups(ldapSearch,userId));

			return ui;
		} catch (SecurityAuthException se) {
			throw se;
		} catch (NamingException ne) {
			throw new SecurityAuthException(ne, null, ne.getMessage());
		}
	}

	private String[] getUserGroups(LDAPSearch ldapSearch,String userId) throws NamingException {

		ArrayList<String> grpList = new ArrayList<String>(); 

		Attributes[] atrs = ldapSearch.multiSearch(this.ldapUserGrpSearchbase, this.ldapUserGrpId + "=*",
				SearchControls.SUBTREE_SCOPE);

		if (atrs == null || atrs.length <= 0)
			return grpList.toArray(new String[0]);

		for (Attributes atr : atrs) {

			String um = this.ldapUserId + "=" + userId + "," + this.ldapUserinfoSearchbase;

			String gid = atr.get(this.ldapUserGrpId).get().toString();

			Attribute at = atr.get(this.ldapUserGrpUserId);

			for (int i = 0; i < at.size(); i++) {
				if (at.get(i).toString().equals(um))
					grpList.add(gid);

			}

		}

		return grpList.toArray(new String[0]);

	}

	@Override
	public void initProperties(Properties prop) throws SecurityAuthException {

		ldapUserinfoSearchbase = prop.getProperty("ldap.user.search.base");
		ldapUserName = LDAPContext.getAttributeMapping(prop, "user.name");

		this.ldapUserGrpSearchbase = prop.getProperty("ldap.user.group.search.base");
		this.ldapUserGrpId = LDAPContext.getAttributeMapping(prop, "group.id");
		this.ldapUserGrpUserId = LDAPContext.getAttributeMapping(prop, "group.user.id");
		ldapUserId=LDAPContext.getAttributeMapping(prop,"user.id");
		
		ldapCtx = new LDAPContext();

		ldapCtx.setFactory(prop.getProperty("ldap.initial.context.factory"))
				.setSecurityAuthentication(prop.getProperty("ldap.context.security.authentication"))
				.setServerUrl(prop.getProperty("ldap.server.url"));

	}

	private LDAPSearch getLDAPSearch(String userId, String password) throws SecurityAuthException {

		try {

			LDAPContext ctx = new LDAPContext(this.ldapCtx.getProperties()); 
		 	
			String ui=this.ldapUserId+"="+userId+","+this.ldapUserinfoSearchbase;			

			ctx.setUser(ui);

			ctx.setPassword(password);

			LDAPSearch ldapSearch = new LDAPSearch(ctx);

			return ldapSearch;
		} catch (Exception e) {

			throw new SecurityAuthException(e, "", "Invalidate User Id or Password.");

		}

	}

}

class UserInfoImpl implements UserInfo, Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private String userId;

	private String userName;

	private String authCode;

	private String userPwd;

	private String[] listGrp;

	@Override
	public String getUserId() {
		return this.userId;
	}

	@Override
	public String getUserName() {
		return this.userName;
	}

	@Override
	public String getAuthCode() {
		return this.authCode;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public void setAuthCode(String authCode) {
		this.authCode = authCode;
	}

	public void setUserGroups(String[] listGrp) {
		this.listGrp = listGrp;
	}

	public void setUserPassword(String userPwd) {
		this.userPwd = userPwd;
	}

	@Override
	public String[] getUserGroups() {
		return listGrp;
	}

	@Override
	public String getUserPassword() { 
		return userPwd;
	}

}
