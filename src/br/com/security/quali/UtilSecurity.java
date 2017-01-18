package br.com.security.quali;

import java.util.Collection;

import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.util.ThreadContext;

import br.com.security.quali.realm.JdbcRealmBlock;

public class UtilSecurity {

	public static String getDateNow(){
	java.util.Date dt = new java.util.Date();

	java.text.SimpleDateFormat sdf = 
	     new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

	return sdf.format(dt);
	}
	
	public static JdbcRealmBlock getRealm() {
		Collection<Realm> realms = ((RealmSecurityManager) ThreadContext.getSecurityManager()).getRealms();
		for (Realm realm : realms) {
			if (realm instanceof JdbcRealmBlock) {
				return (JdbcRealmBlock) realm;
			}
		}
		return null;
	}
}
