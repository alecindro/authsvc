package br.com.security.quali.authc;


public class LogAuthException extends Exception{

	
	private static final long serialVersionUID = 1L;

	public LogAuthException(String message) {
        super(message);
    }
	
	public LogAuthException(String message,Throwable cause) {
        super(message,cause);
    }
}
