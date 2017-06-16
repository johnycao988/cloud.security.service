package com.cly.cloud.security.service.app;

import com.cly.comm.intf.CLYProperties;
import org.springframework.core.env.Environment;

public class ClientAppProperties  implements CLYProperties{

	private Environment env;
	
	public ClientAppProperties(Environment env){
		this.env=env;
	}
	
	@Override
	public String getProperty(String key) {
	 
		return env.getProperty(key);
	}

	@Override
	public void setProperty(String key, String value) {
		
		
	}

}
