	package com.cly.cloud.security.service.app;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.cly.comm.client.http.HttpRequestParam;
import com.cly.security.SecuConst;
import com.cly.security.server.rest.service.User;

@RestController
@RequestMapping("/user")
public class UserRest {

	private User user=new User();

	@RequestMapping(value = "/authAccessPermmison", method = RequestMethod.POST)
	public String authAccessPermmison(HttpServletRequest request,
			@RequestParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		return user.authAccessPermmison(request, jsonMsg);

	}

	@RequestMapping(value = "/validate", method = RequestMethod.POST)
	public String validate(HttpServletRequest request,
			@RequestParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		return user.validate(request, jsonMsg);

	}

	@RequestMapping(value = "/inqAuthCode", method = RequestMethod.POST)
	public String inqAuthCode(HttpServletRequest request,
			@RequestParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		return user.inqAuthCode(request, jsonMsg);

	}

	@RequestMapping(value = "/redirectPageLogin", method = RequestMethod.POST)
	public void directPageLogin(HttpServletRequest request, HttpServletResponse response,
			@RequestParam(SecuConst.USER_ID) String userId, @RequestParam(SecuConst.USER_PW) String userPwd,
			@RequestParam(SecuConst.AUTH_REDIRECT_URL) String redirectUrl) throws IOException {

		user.directPageLogin(request, response, userId, userPwd, redirectUrl);

	}

	@RequestMapping(value = "/msgLogin", method = RequestMethod.POST)
	public String msgLogin(HttpServletRequest request,
			@RequestParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		return user.msgLogin(request, jsonMsg);
	}

	@RequestMapping(value = "/pageLogin", method = RequestMethod.POST)
	public void directPageLogin(HttpServletRequest request, @RequestParam(SecuConst.USER_ID) String userId,
			@RequestParam(SecuConst.USER_PW) String userPwd,
			@RequestParam(SecuConst.AUTH_REDIRECT_URL) String redirectUrl) throws IOException {

		user.pageLogin(request, userId, userPwd, redirectUrl);

	}


}
