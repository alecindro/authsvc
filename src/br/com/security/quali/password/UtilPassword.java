package br.com.security.quali.password;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.shiro.authc.credential.DefaultPasswordService;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.util.SimpleByteSource;

public class UtilPassword {

	private static String regexNumber = "\\d{1}";
	private static String regexAlphebetic = "\\D{1}";
	private static String messageNumber = "A senha deve conter no m�nimo 1 caractere num�rico.";
	private static String messageAlphabetic = "A senha deve conter no m�nimo 1 caractere alfab�tico.";
	private static String messageLenght = "A senha deve conter no m�nimo 8 caracteres.";
	private static String messagePassEmpty = "Favor digitar a senha.";
	private static String messagePassOne = "Favor digitar a senha.";
	private static String messagePassDiff = "Senha n�o confere. Favor digitar as duas senhas iguais.";
	
	public static void validPassword(String[] passwords) throws PasswordException {
		comparePassword(passwords);
		String password = passwords[0];
		validLenght(password);
		validNumber(password);
		validAlphebetic(password);
	}
	
	public static void validPassword(String password) throws PasswordException {
		validLenght(password);
		validNumber(password);
		validAlphebetic(password);
	}

	public static void comparePassword(String[] password)
			throws PasswordException {
		if(password == null){
			throw new PasswordException(messagePassEmpty);
		}
		if(password.length<2){
			throw new PasswordException(messagePassOne);
		}
		if(password[0]== null || password[1]==null){
			throw new PasswordException(messagePassEmpty);
		}
		if(password[0].compareTo(password[1])!=0){
			throw new PasswordException(messagePassDiff);
		}
	}

	private static void validLenght(String password) throws PasswordException {
		if (password.length() < 8) {
			throw new PasswordException(messageLenght);

		}
	}

	private static void validNumber(String password) throws PasswordException {
		Pattern pattern = Pattern.compile(regexNumber);
		Matcher matcher = pattern.matcher(password);
		if (!matcher.find()) {
			throw new PasswordException(messageNumber);
		}
	}

	private static void validAlphebetic(String password)
			throws PasswordException {
		Pattern pattern = Pattern.compile(regexAlphebetic);
		Matcher matcher = pattern.matcher(password);
		if (!matcher.find()) {
			throw new PasswordException(messageAlphabetic);
		}
	}
	
	public static String genPassword(String passwordText){
		return getPasswordService().encryptPassword(passwordText);
	}
	public static boolean comparePassword(String passwordText, String passwordSaved){
		return getPasswordService().passwordsMatch(passwordText, passwordSaved);
	}
	
	private static DefaultPasswordService getPasswordService(){
		DefaultHashService hashService = new DefaultHashService();
		hashService.setHashIterations(512);
		hashService.setHashAlgorithmName(Sha256Hash.ALGORITHM_NAME);
	    hashService.setPrivateSalt(new SimpleByteSource("qualirede")); // Same salt as in shiro.ini, but NOT base64-encoded.
		hashService.setGeneratePublicSalt(true);
		//ParsableHashFormat parsableHashFormat = new Quali1CryptFormat();
		DefaultPasswordService passwordService = new DefaultPasswordService();
		passwordService.setHashService(hashService);
		//passwordService.setHashFormat(parsableHashFormat);		
		return passwordService;

	}

	
	public static void main(String[] args){
		/*
		if(args!=null){
			if(args.length>0){
				System.out.println(genPassword(args[0]));
			}
		}*/
		String passw = genPassword("1234");
		System.out.println(passw);
		System.out.println(comparePassword("1234","$shiro1$SHA-256$512$a3lTqB9S3unK5nDRzXMT6g==$awGAgSh9j2hakzpRdnAn6gG5gq4DzQ82SRRW18lmw9c="));
			
	}

}
