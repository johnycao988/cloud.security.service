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

import net.sf.json.JSONObject;

@RestController
@RequestMapping("/user")
public class UserRest {

	private static final String REQ_URI_AUTH_ACCESS_PERMMISSION = "/authAccessPermmison";
	private static final String REQ_URI_VALIDATE = "/validate";
	private static final String REQ_URI_INQ_AUTH_CODE = "/inqAuthCode";
	private static final String REQ_URI_REDIRECT_PAGE_LOGIN = "/redirectPageLogin";
	private static final String REQ_URI_MSG_LOGIN = "/msgLogin";
	private static final String REQ_URI_PAGE_LOGIN = "/pageLogin";

	private void infoRequestMsg(HttpServletRequest request, String requestUri, String msgInfo) {

		String sm = "A request:" + requestUri + " from " + request.getRemoteHost() + ":" + msgInfo;

		Application.getLogger().info(sm);

	}

	private void infoResponseMsg(HttpServletRequest request, String requestUri, String msgInfo) {

		String sm = "Reponse from " + requestUri + " to " + request.getRemoteHost() + ":" + msgInfo;

		Application.getLogger().info(sm);

	}

	private User user = new User();

	@RequestMapping(value = REQ_URI_AUTH_ACCESS_PERMMISSION, method = RequestMethod.POST)
	public String authAccessPermmison(HttpServletRequest request,
			@RequestParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		infoRequestMsg(request, REQ_URI_AUTH_ACCESS_PERMMISSION, jsonMsg);

		String rtnMsg = user.authAccessPermmison(request, jsonMsg);

		infoResponseMsg(request, REQ_URI_AUTH_ACCESS_PERMMISSION, rtnMsg);

		return rtnMsg;

	}

	@RequestMapping(value = REQ_URI_VALIDATE, method = RequestMethod.POST)
	public String validate(HttpServletRequest request,
			@RequestParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		infoRequestMsg(request, REQ_URI_VALIDATE, jsonMsg);

		String rtnMsg = user.validate(request, jsonMsg);

		infoResponseMsg(request, REQ_URI_VALIDATE, rtnMsg);

		return rtnMsg;
	}

	@RequestMapping(value = REQ_URI_INQ_AUTH_CODE, method = RequestMethod.POST)
	public String inqAuthCode(HttpServletRequest request,
			@RequestParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		infoRequestMsg(request, REQ_URI_INQ_AUTH_CODE, jsonMsg);

		String rtnMsg = user.inqAuthCode(request, jsonMsg);

		infoResponseMsg(request, REQ_URI_INQ_AUTH_CODE, rtnMsg);

		return rtnMsg;

	}

	@RequestMapping(value = REQ_URI_REDIRECT_PAGE_LOGIN, method = RequestMethod.POST)
	public void directPageLogin(HttpServletRequest request, HttpServletResponse response,
			@RequestParam(SecuConst.USER_ID) String userId, @RequestParam(SecuConst.USER_PW) String userPwd,
			@RequestParam(SecuConst.AUTH_REDIRECT_URL) String redirectUrl) throws IOException {

		infoRequestMsg(request, REQ_URI_REDIRECT_PAGE_LOGIN, "User id:" + userId + " Redirect Url:" + redirectUrl);

		user.directPageLogin(request, response, userId, userPwd, redirectUrl);

	}

	@RequestMapping(value = REQ_URI_MSG_LOGIN, method = RequestMethod.POST)
	public String msgLogin(HttpServletRequest request,
			@RequestParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) {

		JSONObject jo = JSONObject.fromObject(jsonMsg);
		jo.remove(SecuConst.USER_PW);
		infoRequestMsg(request, REQ_URI_MSG_LOGIN, jo.toString());

		String rtnMsg = user.msgLogin(request, jsonMsg);

		infoResponseMsg(request, REQ_URI_MSG_LOGIN, rtnMsg);

		return rtnMsg;
	}

	@RequestMapping(value = REQ_URI_PAGE_LOGIN, method = RequestMethod.POST)
	public void directPageLogin(HttpServletRequest request, @RequestParam(SecuConst.USER_ID) String userId,
			@RequestParam(SecuConst.USER_PW) String userPwd,
			@RequestParam(SecuConst.AUTH_REDIRECT_URL) String redirectUrl) throws IOException {

		infoRequestMsg(request, REQ_URI_PAGE_LOGIN, "User id:" + userId + " Redirect Url:" + redirectUrl);

		user.pageLogin(request, userId, userPwd, redirectUrl);

	}

}
