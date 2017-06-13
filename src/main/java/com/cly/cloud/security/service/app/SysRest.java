package com.cly.cloud.security.service.app;

 
 
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cly.comm.util.JSONUtil;
import com.cly.security.server.SecurityServiceMgr;
 

@RestController

public class SysRest {

	@RequestMapping("/refresh")
	public String refreshApp() {

		SecurityServiceMgr.refresh();
		return "Refreshed.";
	}

	@RequestMapping("/health")
	public String health() {
		
		Application.getLogger().info("Health check.");
		return JSONUtil.getMSHealthCheckResponse();
	}

}
