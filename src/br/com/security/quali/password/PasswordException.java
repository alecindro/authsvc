package br.com.security.quali.password;

public class PasswordException extends Exception{
	
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
     * Constructs a new BlockedException.
     *
     * @param message the reason for the exception
     */
    public PasswordException(String message) {
        super(message);
    }

    /**
     * Constructs a new BlockedException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public PasswordException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new BlockedException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public PasswordException(String message, Throwable cause) {
        super(message, cause);
    }
}
