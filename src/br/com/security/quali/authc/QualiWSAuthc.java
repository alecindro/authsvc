package br.com.security.quali.authc;

import java.util.Set;

import javax.annotation.Resource;
import javax.servlet.ServletContext;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.env.WebEnvironment;
import org.apache.shiro.web.filter.mgt.FilterChainResolver;
import org.apache.shiro.web.servlet.AbstractShiroFilter;
import org.apache.shiro.web.util.WebUtils;

public class QualiWSAuthc extends AbstractShiroFilter implements
		SOAPHandler<SOAPMessageContext> {

	public void init(ServletContext servletContext) throws Exception {
		setServletContext(servletContext);
		WebEnvironment env = WebUtils.getRequiredWebEnvironment(servletContext);
		setSecurityManager(env.getWebSecurityManager());
		FilterChainResolver resolver = env.getFilterChainResolver();
		if (resolver != null) {
			setFilterChainResolver(resolver);
		}
	}

	public void close(MessageContext arg0) {
		// TODO Auto-generated method stub

	}

	public boolean handleFault(SOAPMessageContext arg0) {
		// TODO Auto-generated method stub
		return false;
	}

	public boolean handleMessage(SOAPMessageContext messageContext) {
		Boolean isResponse = (Boolean) messageContext
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (!isResponse) {
			SOAPMessage soapMsg = messageContext.getMessage();
			try {
				SOAPEnvelope soapEnv = soapMsg.getSOAPPart().getEnvelope();
				SOAPHeader soapHeader = soapEnv.getHeader();
				ServletContext servletContext = getServletContext(messageContext);
				init(servletContext);
				AuthenticationToken authenticationToken = createToken(soapHeader);
				Subject subject = SecurityUtils.getSubject();
				SecurityUtils.getSecurityManager().login(subject,
						authenticationToken);
			} catch (SOAPException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
		return true;
	}

	protected AuthenticationToken createToken(SOAPHeader soapHeader) {
		if (soapHeader.getElementsByTagName("wsse:Username") == null) {

		}
		if (soapHeader.getElementsByTagName("wsse:Password") == null) {

		}
		String userName = soapHeader.getElementsByTagName("wsse:Username")
				.item(0).getFirstChild().getNodeValue();
		String password = soapHeader.getElementsByTagName("wsse:Password")
				.item(0).getFirstChild().getNodeValue();
		String nonce = null;
		if (soapHeader.getElementsByTagName("wsse:Nonce") != null) {
			nonce = soapHeader.getElementsByTagName("wsse:Nonce").item(0)
					.getFirstChild().getNodeValue();
			password = parseNonce(password, nonce);
		}

		return new UsernamePasswordToken(userName, password.toCharArray());
	}

	protected String parseNonce(String password, String nonce) {
		return password;
	}

	protected void login() {

	}

	public Set<QName> getHeaders() {
		// TODO Auto-generated method stub
		return null;
	}

	public ServletContext getServletContext(SOAPMessageContext messageContext) {
		return (ServletContext) messageContext
				.get(MessageContext.SERVLET_CONTEXT);
	}
}
