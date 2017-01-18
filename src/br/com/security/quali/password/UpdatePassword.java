package br.com.security.quali.password;

import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.web.util.WebUtils;

import br.com.security.quali.UtilSecurity;

@WebServlet("/updatePassw")
public class UpdatePassword extends javax.servlet.http.HttpServlet{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		Enumeration<String> params =  req.getParameterNames();
		String[] passwords = new String[2];
		int i = 0;
		while(params.hasMoreElements()){
			if(i>1){
				break;
			}
			String param = params.nextElement();
			passwords[i] = req.getParameter(param);
			i = i+1;
		}
			
		try {
			UtilPassword.validPassword(passwords);
			String username = (String) SecurityUtils.getSubject().getPrincipal();
			UtilSecurity.getRealm().updatePassword(username, passwords[0]);
			String urlInit = UtilSecurity.getRealm().getFormAuthenticationFilter().getSuccessUrl();
			WebUtils.redirectToSavedRequest(req, resp, urlInit);
		} catch (PasswordException e) {
			
			req.setAttribute("error_update_passw", e.getMessage());
			req.getRequestDispatcher("/alterPassword.jsp").forward(req, resp);
		}
				
	}
	
	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(req, resp);
	}

}
