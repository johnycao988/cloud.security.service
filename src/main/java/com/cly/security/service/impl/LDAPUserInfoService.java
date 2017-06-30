package com.cly.security.service.impl;

import java.util.ArrayList;
import java.util.Properties;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;

import com.cly.cache.CacheMgr;
import com.cly.cache.KeyValue;
import com.cly.cloud.security.service.app.Application;
import com.cly.comm.util.IDUtil;
import com.cly.err.ErrorHandler;
import com.cly.err.ErrorHandlerMgr;
import com.cly.ldap.LDAPContext;
import com.cly.ldap.LDAPSearch;
import com.cly.security.AuthPermission;
import com.cly.security.PermissionAuthResult;
import com.cly.security.SecuConst;
import com.cly.security.SecurityAuthException;
import com.cly.security.UserInfo;
import com.cly.security.server.SecurityServiceMgr;

import net.sf.ehcache.Cache;
import net.sf.ehcache.Element;
import net.sf.json.JSONObject;

import com.cly.security.UserAuthService;

public class LDAPUserInfoService implements UserAuthService {

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

			UserInfo ui = new UserInfo(userId, slUserName, IDUtil.getRandomBase64UUID(),
					this.getUserGroups(ldapSearch, userId));

			SecurityServiceMgr.getKVService().set(SecuConst.AUTH_KV_AUTHCODE + ui.getAuthCode(), ui.toString(),
					30 * 60);

			this.setUserInfoToCache(ui);

			return ui;

		} catch (SecurityAuthException se) {
			throw se;
		} catch (NamingException ne) {
			throw new SecurityAuthException(ne, null, ne.getMessage());
		}
	}

	private String[] getUserGroups(LDAPSearch ldapSearch, String userId) throws NamingException {

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
		ldapUserId = LDAPContext.getAttributeMapping(prop, "user.id");

		ldapCtx = new LDAPContext();

		ldapCtx.setFactory(prop.getProperty("ldap.initial.context.factory"))
				.setSecurityAuthentication(prop.getProperty("ldap.context.security.authentication"))
				.setServerUrl(prop.getProperty("ldap.server.url"));

	}

	private LDAPSearch getLDAPSearch(String userId, String password) throws SecurityAuthException {

		try {

			LDAPContext ctx = new LDAPContext(this.ldapCtx.getProperties());

			String ui = this.ldapUserId + "=" + userId + "," + this.ldapUserinfoSearchbase;

			ctx.setUser(ui);

			ctx.setPassword(password);

			LDAPSearch ldapSearch = new LDAPSearch(ctx);

			return ldapSearch;
		} catch (Exception e) {

			String errCode = "SECU-00001";
			ErrorHandler eh = ErrorHandlerMgr.getErrorHandler();
			throw new SecurityAuthException(errCode, eh.getErrorMessage(errCode));
 
		}

	}

	private void setUserInfoToCache(UserInfo ui) {

		if (ui == null)
			return;

		Cache sessCache = CacheMgr.getCache(SecuConst.AUTH_CODE_CACHE);

		sessCache.put(new Element(ui.getAuthCode(), ui));
		
		Application.getLogger().debug("Put User Info to Cache:"+ui.toString());

	}

	private void deleteUserInfo(UserInfo ui) throws SecurityAuthException {

		Cache sessCache = CacheMgr.getCache(SecuConst.AUTH_CODE_CACHE);

		Element eu = sessCache.get(ui.getAuthCode());

		sessCache.removeElement(eu);

		SecurityServiceMgr.getKVService().delete(SecuConst.AUTH_KV_AUTHCODE + ui.getAuthCode());

	}

	private UserInfo getUserInfo(String authCode) throws SecurityAuthException {

		Cache sessCache = CacheMgr.getCache(SecuConst.AUTH_CODE_CACHE);

		UserInfo ui = null;

		Element eu = sessCache.get(authCode);

		if (eu != null){
		
			ui = (UserInfo) eu.getObjectValue();
			Application.getLogger().debug("Get User Info from Session OK:"+ui.toString());
		}

		if (ui == null) {

			KeyValue kvs = SecurityServiceMgr.getKVService();

			String sui = kvs.get(SecuConst.AUTH_KV_AUTHCODE+authCode);
			
			Application.getLogger().debug("Get User Info from KV:"+sui );

			if (sui != null) {
				ui = new UserInfo(JSONObject.fromObject(sui));
				this.setUserInfoToCache(ui);
			}
		}

		if (ui == null) {
			
			Application.getLogger().debug("Can't get User Info");
			
			String errCode = "SECU-00004";
			ErrorHandler eh = ErrorHandlerMgr.getErrorHandler();
			throw new SecurityAuthException(errCode, eh.getErrorMessage(errCode));
		}

		return ui;
	}

	@Override
	public boolean logout(String userId, String authCode) throws SecurityAuthException {

		UserInfo ui = this.getUserInfo(authCode);

		if (ui != null && ui.getUserId() != null && ui.getUserId().equals(userId)) {

			deleteUserInfo(ui);

			return true;
		}

		return false;
	}

	@Override
	public boolean authenticate(String userId, String authCode) throws SecurityAuthException {

		UserInfo ui = this.getUserInfo(authCode);

		if (ui != null && ui.getUserId().equals(userId))
			return true;

		return false;
	}

	private AuthPermission checkPermission(String permissionName, UserInfo ui) {

		boolean bPermitted = false;

		if (ui.getUserGroups() != null)
			for (String sg : ui.getUserGroups()) {
				if (sg.equals(permissionName)) {
					bPermitted = true;
					break;
				}

			}

		return new AuthPermission(permissionName, bPermitted);

	}

	@Override
	public PermissionAuthResult authPermissions(String userId, String authCode, String[] authPermissionNames)
			throws SecurityAuthException {

		UserInfo ui = this.getUserInfo(authCode);

		if (ui != null && ui.getUserId().equals(userId)) {

			ArrayList<AuthPermission> alList = new ArrayList<AuthPermission>();

			for (String spn : authPermissionNames) {
				alList.add(checkPermission(spn, ui));
			}

			return new PermissionAuthResult(alList);

		} else {
			String errCode = "SECU-00004";
			ErrorHandler eh = ErrorHandlerMgr.getErrorHandler();
			throw new SecurityAuthException(errCode, eh.getErrorMessage(errCode));

		}

	}

}
