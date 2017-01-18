package br.com.security.quali.authc;

import org.apache.shiro.authc.AuthenticationException;

public class BlockedException extends AuthenticationException{

	
	private static final long serialVersionUID = 1L;

    /**
     * Creates a new BlockedException.
     */
    public BlockedException() {
        super();
    }

    /**
     * Constructs a new BlockedException.
     *
     * @param message the reason for the exception
     */
    public BlockedException(String message) {
        super(message);
    }

    /**
     * Constructs a new BlockedException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public BlockedException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new BlockedException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public BlockedException(String message, Throwable cause) {
        super(message, cause);
    }
}
