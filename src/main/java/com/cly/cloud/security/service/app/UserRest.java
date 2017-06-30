package com.cly.cloud.security.service.app;

import java.io.IOException; 
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController; 
import com.cly.comm.client.http.HttpRequestParam;
import com.cly.comm.util.IDUtil; 
import com.cly.comm.util.JSONUtil;
import com.cly.err.ErrorHandler;
import com.cly.err.ErrorHandlerMgr;
import com.cly.security.PermissionAuthResult;
import com.cly.security.SecuConst;
import com.cly.security.SecurityAuthException;
import com.cly.security.UserInfo;
import com.cly.security.server.SecurityServiceMgr; 
import net.sf.json.JSONObject;

@RestController
@RequestMapping("/user")
public class UserRest {

	private static final String REQ_URI_AUTH_ACCESS_PERMMISSION = "/authAccessPermmison";
	private static final String REQ_URI_VALIDATE = "/validate";
	private static final String REQ_URI_MSG_LOGOUT = "/msgLogout";
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

	@RequestMapping(value = REQ_URI_AUTH_ACCESS_PERMMISSION, method = RequestMethod.POST)
	public String authAccessPermmison(HttpServletRequest request,
			@RequestParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) throws SecurityAuthException {

		infoRequestMsg(request, REQ_URI_AUTH_ACCESS_PERMMISSION, jsonMsg);

		UserInfo ui = new UserInfo(JSONObject.fromObject(jsonMsg));

		PermissionAuthResult par = SecurityServiceMgr.getAuthUserService().authPermissions(ui.getUserId(),
				ui.getAuthCode(), ui.getUserGroups());

		String rtnMsg = par.toString();

		infoResponseMsg(request, REQ_URI_AUTH_ACCESS_PERMMISSION, rtnMsg);

		return rtnMsg;

	}

	@RequestMapping(value = REQ_URI_VALIDATE, method = RequestMethod.POST)
	public String validate(HttpServletRequest request,
			@RequestParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) throws SecurityAuthException {

		infoRequestMsg(request, REQ_URI_VALIDATE, jsonMsg);

		UserInfo ui = new UserInfo(JSONObject.fromObject(jsonMsg));

		boolean bAuth = SecurityServiceMgr.getAuthUserService().authenticate(ui.getUserId(), ui.getAuthCode());

		JSONObject jr = null;

		if (bAuth)
			jr = JSONUtil.initSuccess();
		else {

			String errCode = "SECU-00004";
			ErrorHandler eh = ErrorHandlerMgr.getErrorHandler();
			jr = JSONUtil.initFailed(errCode, eh.getErrorMessage(errCode));

		}

		String rtnMsg = jr.toString();

		infoResponseMsg(request, REQ_URI_VALIDATE, rtnMsg);

		return rtnMsg;
	}

	@RequestMapping(value = REQ_URI_INQ_AUTH_CODE, method = RequestMethod.POST)
	public String inqAuthCode(HttpServletRequest request,
			@RequestParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) throws SecurityAuthException {

		infoRequestMsg(request, REQ_URI_INQ_AUTH_CODE, jsonMsg);

		JSONObject msg = JSONObject.fromObject(jsonMsg);

		String inqAuthCode = JSONUtil.getString(msg, SecuConst.AUTH_INQ_CODE);

		String key = SecuConst.AUTH_KV_INQ_AUTHCODE + inqAuthCode;

		String sui = SecurityServiceMgr.getKVService().get(key);

		SecurityServiceMgr.getKVService().delete(key);

		JSONObject jr = null;

		if (sui != null) {
			UserInfo ui = new UserInfo(JSONObject.fromObject(sui));
			jr = JSONUtil.initSuccess();
			jr.put(SecuConst.AUTH_CODE, ui.getAuthCode());
			jr.put(SecuConst.USER_ID, ui.getUserId());

		} else {

			String errCode = "SECU-00004";
			ErrorHandler eh = ErrorHandlerMgr.getErrorHandler();
			jr = JSONUtil.initFailed(errCode, eh.getErrorMessage(errCode));

		}

		String rtnMsg = jr.toString();

		infoResponseMsg(request, REQ_URI_INQ_AUTH_CODE, rtnMsg);

		return rtnMsg;

	}

	@RequestMapping(value = REQ_URI_REDIRECT_PAGE_LOGIN, method = RequestMethod.POST)
	public void redirectPageLogin(HttpServletRequest request, HttpServletResponse response,
			@RequestParam(SecuConst.USER_ID) String userId, @RequestParam(SecuConst.USER_PW) String userPwd,
			@RequestParam(SecuConst.AUTH_REDIRECT_URL) String redirectUrl) throws IOException, SecurityAuthException {

		infoRequestMsg(request, REQ_URI_REDIRECT_PAGE_LOGIN, "User id:" + userId + " Redirect Url:" + redirectUrl);

		UserInfo ui = SecurityServiceMgr.getAuthUserService().login(userId, userPwd);

		String inqAuthCode = IDUtil.getRandomBase64UUID();

		String key = SecuConst.AUTH_KV_INQ_AUTHCODE + inqAuthCode;

		SecurityServiceMgr.getKVService().set(key, ui.toString());

		String url = redirectUrl + "?" + SecuConst.AUTH_INQ_CODE + "=" + inqAuthCode;

		response.sendRedirect(url);

	}

	@RequestMapping(value = REQ_URI_MSG_LOGIN, method = RequestMethod.POST)
	public String msgLogin(HttpServletRequest request,
			@RequestParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) throws SecurityAuthException {

		JSONObject jo = JSONObject.fromObject(jsonMsg);
		jo.remove(SecuConst.USER_PW);
		infoRequestMsg(request, REQ_URI_MSG_LOGIN, jo.toString());

		UserInfo ui = SecurityServiceMgr.getAuthUserService().login(JSONUtil.getString(jo, SecuConst.USER_ID),
				JSONUtil.getString(jo, SecuConst.USER_PW));

		JSONObject jr = JSONUtil.initSuccess();

		jr.put(SecuConst.AUTH_CODE, ui.getAuthCode());
		jr.put(SecuConst.USER_ID, ui.getUserId());

		String rtnMsg = jr.toString();

		infoResponseMsg(request, REQ_URI_MSG_LOGIN, rtnMsg);

		return rtnMsg;
	}

	@RequestMapping(value = REQ_URI_MSG_LOGOUT, method = RequestMethod.POST)
	public String msgLogout(HttpServletRequest request,
			@RequestParam(HttpRequestParam.REQ_JSON_MESSAGE_NAME) String jsonMsg) throws SecurityAuthException {

		infoRequestMsg(request, REQ_URI_MSG_LOGIN, jsonMsg);

		UserInfo ui = new UserInfo(JSONObject.fromObject(jsonMsg));

		JSONObject jr;

		if (SecurityServiceMgr.getAuthUserService().logout(ui.getUserId(), ui.getAuthCode())) {
			jr = JSONUtil.initSuccess();
		} else {
			String errCode = "SECU-00004";
			ErrorHandler eh = ErrorHandlerMgr.getErrorHandler();
			jr = JSONUtil.initFailed(errCode, eh.getErrorMessage(errCode));

		}

		String rtnMsg = jr.toString();

		infoResponseMsg(request, REQ_URI_MSG_LOGOUT, rtnMsg);

		return rtnMsg;
	}

	@RequestMapping(value = REQ_URI_PAGE_LOGIN, method = RequestMethod.POST)
	public String pageLogin(HttpServletRequest request, @RequestParam(SecuConst.USER_ID) String userId,
			@RequestParam(SecuConst.USER_PW) String userPwd) throws IOException, SecurityAuthException {

		infoRequestMsg(request, REQ_URI_PAGE_LOGIN, "User id:" + userId);

		UserInfo ui = SecurityServiceMgr.getAuthUserService().login(userId, userPwd);

		JSONObject jr = JSONUtil.initSuccess();

		jr.put(SecuConst.AUTH_CODE, ui.getAuthCode());
		jr.put(SecuConst.USER_ID, ui.getUserId());

		String rtnMsg = jr.toString();

		infoResponseMsg(request, REQ_URI_MSG_LOGIN, rtnMsg);

		return rtnMsg;

	}

}
