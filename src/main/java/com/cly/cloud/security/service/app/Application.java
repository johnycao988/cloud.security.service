package com.cly.cloud.security.service.app;


import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication; 
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod; 

import com.cly.comm.client.config.ConfigClient;
import com.cly.logging.LoggingManager;
import com.cly.security.SecuConst;
import com.cly.security.server.SecurityServiceMgr; 

@SpringBootApplication
@Controller
public class Application   {

	@Autowired
	private Environment env;  
	
	@Value("${app.info}")
    private String appInfo;

	@RequestMapping(value = "/loginPage", method = RequestMethod.GET)
	public String authLogin() {
		 
		return "authLogin";
	}

	
	@RequestMapping("/")
	public String version(Model m) {
		
		  m.addAttribute("appInfo", appInfo);
          return "welcome"; 
	}

	@RequestMapping("/info")
	public String info(Model m) {
		return version(m);
	}

 
	@RequestMapping("/login")
	public String login(Model m,HttpServletRequest request) {
		
		m.addAttribute(SecuConst.AUTH_REDIRECT_URL,request.getParameter(SecuConst.AUTH_REDIRECT_URL));
		
		return "authLogin";
	}

	


	public void init(){
		 
		String configAuthCode = env.getProperty(ConfigClient.AUTH_CODE);
		String configServerUrl = env.getProperty(ConfigClient.CONFIG_SERVICE_URL);
		String rootConfigPath = env.getProperty(ConfigClient.ROOT_CONFIG_PATH);

		ConfigClient.init(configAuthCode, configServerUrl, rootConfigPath);
		
		SecurityServiceMgr.init();
	}
	
	public static void main(String[] args) { 
		
		Application app=SpringApplication.run(Application.class, args).getBean(Application.class);
		
		app.init();

	}
	
	public static Logger getLogger(){
		
		return LoggingManager.getLogger("cloud.security.service");
		
	}

}
