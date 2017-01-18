package br.com.security.quali.authc;

import java.io.IOException;
import java.util.Calendar;
import java.util.TimeZone;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.com.security.quali.UtilSecurity;
import br.com.security.quali.realm.JdbcRealmBlock;

public class QualiFormAuthc extends FormAuthenticationFilter {

	private static final Logger log = LoggerFactory
			.getLogger(QualiFormAuthc.class);

	protected String msgLoginUnsucess = "Login attempt was unsuccessful.";
	protected String successAuthcAttribute = "sucessAuthc";
	protected String failAuthcAttribute = "failAuthc";
	protected String alterPasswordUrl;

	protected String timezoneParam = "timezone";
	private Integer limitDays = 180;

	@Override
	protected void setFailureAttribute(ServletRequest request,
			AuthenticationException ae) {
		request.setAttribute(getFailureKeyAttribute(), msgLoginUnsucess);
	}

	protected void setBlockedAttribute(ServletRequest request, String message) {
		request.setAttribute(getFailureKeyAttribute(), message);
	}
	@Override
	protected boolean isAccessAllowed(ServletRequest request,
			ServletResponse response, Object mappedValue) {
		// TODO Auto-generated method stub
		String _uri = WebUtils.getPathWithinApplication((HttpServletRequest)request);
		if(super.isAccessAllowed(request, response, mappedValue)){			
				if(_uri.endsWith(getLoginUrl())){
					try {
						WebUtils.redirectToSavedRequest(request, response, getSuccessUrl());						
					} catch (IOException e) {
						e.printStackTrace();
						return false;
					}
				}
				return true;
		}
		return false;
	}

	@Override
	protected boolean executeLogin(ServletRequest request,
			ServletResponse response) throws Exception {
		AuthenticationToken token = createToken(request, response);
		Subject subject = getSubject(request, response);
		if (token == null) {
			String msg = "createToken method implementation returned null. A valid non-null AuthenticationToken "
					+ "must be created in order to execute a login attempt.";
			log.debug(msg);
			throw new IllegalStateException(msg);
		}
		TimeZone timeZone = getTimezone(request);
		try {
			UtilSecurity.getRealm().setFormAuthenticationFilter(this);
			subject.login(token);
			addInfoLogin(subject, token);
			logSuccessLogin(subject, token, timeZone);
			if (UtilSecurity.getRealm().alterPassword(token, limitDays)) {
				WebUtils.redirectToSavedRequest(request, response,
						alterPasswordUrl);
				return false;
			}
			WebUtils.getAndClearSavedRequest(request);
			return onLoginSuccess(token, subject, request, response);
		} catch (UnknownAccountException e) {
			log.debug(e.getMessage());
			setFailureAttribute(request, e);
			return true;
		} catch (BlockedException e) {
			log.debug(e.getMessage());
			logUnSuccessLogin(subject, token, timeZone);
			setBlockedAttribute(request, e.getMessage());
			return true;
		} catch (AuthenticationException e) {
			log.debug(e.getMessage());
			logUnSuccessLogin(subject, token, timeZone);
			setFailureAttribute(request, e);
			return true;
		}
	}

	protected void addInfoLogin(Subject subject, AuthenticationToken token) {
		JdbcRealmBlock jdbcRealmBlock = UtilSecurity.getRealm();
		subject.getSession(false).setAttribute(successAuthcAttribute,
				jdbcRealmBlock.getAuthSucess(token));
		subject.getSession(false).setAttribute(failAuthcAttribute,
				jdbcRealmBlock.getAuthFail(token));
		subject.getSession(false).setAttribute("failLimit",
				jdbcRealmBlock.getFailLoginLimit());
	}

	private void logSuccessLogin(Subject subject, AuthenticationToken token,
			TimeZone timezone) {
		JdbcRealmBlock realm = UtilSecurity.getRealm();
		if (realm != null) {
			try {
				realm.logSucess(token, timezone);
			} catch (LogAuthException e) {
				log.error(e.getMessage());
			}
		}

	}

	private void logUnSuccessLogin(Subject subject, AuthenticationToken token,
			TimeZone timezone) {
		JdbcRealmBlock realm = UtilSecurity.getRealm();
		if (realm != null) {
			try {
				realm.logUnSucess(token, timezone);
			} catch (LogAuthException e) {
				log.error(e.getMessage());
			}
		}
	}

	public String getMsgLoginUnsucess() {
		return msgLoginUnsucess;
	}

	public void setMsgLoginUnsucess(String msgLoginUnsucess) {
		this.msgLoginUnsucess = msgLoginUnsucess;
	}

	protected TimeZone getTimezone(ServletRequest request) {
		try {
			String strFromJavaScript = request.getParameter("timezone");
			int timeZone = Integer.parseInt(strFromJavaScript);
			if (timeZone >= 0) {
				strFromJavaScript = "+" + timeZone;
			}
			return TimeZone.getTimeZone("GMT" + strFromJavaScript);
		} catch (java.lang.NumberFormatException e) {
			log.error("Parametro timezone nao esta vindo no formato numerico");
			return Calendar.getInstance().getTimeZone();
		}
	}

	public String getTimezoneParam() {
		return timezoneParam;
	}

	public void setTimezoneParam(String timezoneParam) {
		this.timezoneParam = timezoneParam;
	}

	public String getSuccessAuthcAttribute() {
		return successAuthcAttribute;
	}

	public void setSuccessAuthcAttribute(String successAuthcAttribute) {
		this.successAuthcAttribute = successAuthcAttribute;
	}

	public String getFailAuthcAttribute() {
		return failAuthcAttribute;
	}

	public void setFailAuthcAttribute(String failAuthcAttribute) {
		this.failAuthcAttribute = failAuthcAttribute;
	}

	public String getAlterPasswordUrl() {
		return alterPasswordUrl;
	}

	public void setAlterPasswordUrl(String alterPasswordUrl) {
		this.alterPasswordUrl = alterPasswordUrl;
	}

	public Integer getLimitDays() {
		return limitDays;
	}

	public void setLimitDays(Integer limitDays) {
		this.limitDays = limitDays;
	}

}
