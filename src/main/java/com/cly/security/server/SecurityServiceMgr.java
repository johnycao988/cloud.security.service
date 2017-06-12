package com.cly.security.server;
 
import java.util.Properties;

import org.apache.log4j.xml.DOMConfigurator; 

import com.cly.cache.CacheMgr;
import com.cly.cache.KeyValue;
import com.cly.cloud.security.service.app.Application;
import com.cly.comm.client.config.ConfigClient;
import com.cly.err.ErrorHandler;
import com.cly.err.ErrorHandlerMgr;
import com.cly.logging.LoggingManager;
import com.cly.security.SecurityAuthException;
import com.cly.security.UserInfoService;

public class SecurityServiceMgr {

	private static Properties securityProperties = null;

	private static UserInfoService userInfoService = null;

	private static KeyValue kvService;

	private SecurityServiceMgr() {

	}

	public static Properties getProperties() {

		return securityProperties;
	}

	public static String refresh() {

		Application.getLogger().info("Start to refresh security server configurations...");

		init();

		return "Security Server Refresh completed.";
	}

	public static UserInfoService getUserInfoService() throws SecurityAuthException {

		if (userInfoService == null) {

			userInfoService = (UserInfoService) createServiceInstance("cloud.security.userinfo.service");

			userInfoService.initProperties(getProperties());

		}

		return userInfoService;

	}

	public static KeyValue getKVService() throws SecurityAuthException {

		if (kvService == null) {

			kvService = (KeyValue) createServiceInstance("cloud.security.kv.service");

			kvService.initProperties(getProperties());

		}

		return kvService;

	}

	private static Object createServiceInstance(String propName) throws SecurityAuthException {

		ErrorHandler eh = ErrorHandlerMgr.getErrorHandler();

		Properties p = getProperties();

		String className = p.getProperty(propName);

		if (className == null) {
			String errCode = "SECU-00002";
			String errMsg = eh.getErrorMessage(errCode, propName);
			Application.getLogger().error(errMsg);
			throw new SecurityAuthException(errCode, errMsg);
		}

		try {

			return Class.forName(className).newInstance();

		} catch (Exception e) {
			String errCode = "SECU-00003";
			String errMsg = eh.getErrorMessage(errCode, propName);
			Application.getLogger().error(errMsg);
			throw new SecurityAuthException(e, errCode, errMsg);
		}
	}

	public static void init() {

		try {

			initLog();

			initErrorHandler();

			initCache();

			initSecurityProperties();

			Application.getLogger().info("Initialized completely.");

		} catch (Exception e) {

			Application.getLogger().error("Initial error:", e);

		}
	}

	private static void initSecurityProperties() {

		try {

			securityProperties = null;

			userInfoService = null;

			kvService = null;

			Application.getLogger().info("Initializing Properties...");

			securityProperties = ConfigClient.getProperties("/cloud.security/cloud.security.server.properties");

		} catch (Exception e) {

			Application.getLogger().error("Init Properties error:", e);

		}
	}

	private static void initCache() {
		try {

			Application.getLogger().info("Initializing Cache...");

			CacheMgr.init(ConfigClient.getInputStream("/cloud.security/cloud.security.server.cache.xml"));

		} catch (Exception e) {

			Application.getLogger().error("Init cache error:", e);

		}

	}

	private static void initErrorHandler() {
		try {

			Application.getLogger().info("Initializing Error Handler...");

			ErrorHandlerMgr.clear();
			ErrorHandlerMgr
					.addConfigFile(ConfigClient.getInputStream("/cloud.security/cloud.security.err.handler.xml"));
		} catch (Exception e) {

			Application.getLogger().error("Init error handler:", e);

		}

	}

	private static void initLog() {

		try {

			
/*
 * Log4j2
 *
  			LogManager.shutdown();

			ConfigurationSource cs = new ConfigurationSource(
					ConfigClient.getInputStream("/cloud.security/cloud.security.server.log4j.xml"));
			
			Configurator.initialize(null, cs);
			
			log4j2 */ 

			DOMConfigurator.configure(ConfigClient.getDocuement("/cloud.security/cloud.security.server.log4j.xml").getDocumentElement());
			
	 
		} catch (Exception e) {

			LoggingManager.systemErr(e);

		}

	}

}
