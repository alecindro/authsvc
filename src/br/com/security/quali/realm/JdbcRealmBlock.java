package br.com.security.quali.realm;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;

import javax.inject.Inject;
import javax.sql.DataSource;

import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.util.JdbcUtils;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import br.com.cuidebem.Emailsvc;
import br.com.security.quali.UtilSecurity;
import br.com.security.quali.authc.BlockedException;
import br.com.security.quali.authc.LogAuthException;
import br.com.security.quali.model.InfoAuthc;
import br.com.security.quali.password.PasswordException;
import br.com.security.quali.password.UtilPassword;

public class JdbcRealmBlock extends JdbcRealm {

	private static final Logger log = LoggerFactory.getLogger(JdbcRealmBlock.class);

	protected static final String DEFAULT_BLOCK_QUERY = " update users set blocked = 1 where email = ? ";
	protected static final String DEFAULT_LOG_QUERY = "insert into logauth(login,data,sucess) values(?,?,?)";
	protected static final String DEFAULT_SUCESS_LOG_QUERY = "select sucess from logauth where login = ? order by data desc limit ?";
	protected static final String DEFAULT_BLOCK_MESSAGE = "user blocked. Contact administrator";
	protected String blockQuery = DEFAULT_BLOCK_QUERY;
	protected String msgLoginBlocked = DEFAULT_BLOCK_MESSAGE;
	protected String logQuery = DEFAULT_LOG_QUERY;
	protected String successLogQuery = DEFAULT_SUCESS_LOG_QUERY;
	protected String failLoginQuery;
	protected String sucessLoginQuery;
	protected String updateLoginQuery;
	protected String updatePasswordQuery;
	protected String sucessUrlCuidador;
	protected String sucessUrlresp;
	private Integer numberRetrieValue = 10;
	private Integer failLoginLimit;
	private FormAuthenticationFilter formAuthenticationFilter;

	private Emailsvc emailSVC;

	public Integer getFailLoginLimit() {
		return failLoginLimit;
	}

	public void setFailLoginLimit(Integer failLoginLimit) {
		this.failLoginLimit = failLoginLimit;
	}

	public String getMsgLoginBlocked() {
		return msgLoginBlocked;
	}

	public void setMsgLoginBlocked(String msgLoginBlocked) {
		this.msgLoginBlocked = msgLoginBlocked;
	}

	private String getUsername(AuthenticationToken token) {
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		return upToken.getUsername();
	}

	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		String username = getUsername(token);

		// Null username is invalid
		if (username == null) {
			throw new AccountException("Null usernames are not allowed by this realm.");
		}

		Connection conn = null;
		SimpleAuthenticationInfo info = null;
		try {
			conn = dataSource.getConnection();

			Object[] result = getPasswordForUser(conn, username);
			String password = (String) result[0];
			boolean blocked = (Boolean) result[1];
			Object activation = result[2];

			if (password == null) {
				throw new UnknownAccountException("No account found for user [" + username + "]");
			}
			if (activation == null) {
				emailSVC = javax.enterprise.inject.spi.CDI.current().select(Emailsvc.class).get();
				emailSVC.confirmarEmail(username);
				throw new BlockedException("Favor ativar a sua conta. Enviamos um novo email solicitando a ativação.");
			}

			if (blocked) {
				emailSVC = javax.enterprise.inject.spi.CDI.current().select(Emailsvc.class).get();
				emailSVC.desbloquearEmail(username);
				throw new BlockedException(getMsgLoginBlocked());
			}

			info = new SimpleAuthenticationInfo(username, password.toCharArray(), getName());

		} catch (SQLException e) {
			final String message = "There was a SQL error while authenticating user [" + username + "]";
			if (log.isErrorEnabled()) {
				log.error(message, e);
			}

			// Rethrow any SQL errors as an authentication exception
			throw new AuthenticationException(message, e);
		} finally {
			JdbcUtils.closeConnection(conn);
		}

		return info;
	}

	@SuppressWarnings("resource")
	private Object[] getPasswordForUser(Connection conn, String username) throws SQLException {

		Object[] result = new Object[4];

		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			ps = conn.prepareStatement(authenticationQuery);
			ps.setString(1, username);

			// Execute query
			rs = ps.executeQuery();

			// Loop over results - although we are only expecting one result,
			// since usernames should be unique
			boolean foundResult = false;
			while (rs.next()) {

				// Check to ensure only one row is processed
				if (foundResult) {
					throw new AuthenticationException(
							"More than one user row found for user [" + username + "]. Usernames must be unique.");
				}

				result[0] = rs.getString(1);
				result[1] = rs.getBoolean(2);
				result[2] = rs.getObject(3);
				result[3] = rs.getObject(4);
				if ((int) result[3] == 2) {
					formAuthenticationFilter.setSuccessUrl(sucessUrlCuidador);
				} else {
					formAuthenticationFilter.setSuccessUrl(sucessUrlresp);
				}
				foundResult = true;
			}
		} finally {
			JdbcUtils.closeResultSet(rs);
			JdbcUtils.closeStatement(ps);
		}

		return result;
	}

	private void blockUser(AuthenticationToken token, DataSource _dataSource) throws BlockedException {
		Connection conn = null;
		PreparedStatement ps = null;
		try {
			String username = getUsername(token);
			conn = _dataSource.getConnection();
			ps = conn.prepareStatement(blockQuery);
			ps.setString(1, username);
			ps.executeUpdate();
		} catch (Exception e) {
			throw new BlockedException(e.getMessage(), e);
		} finally {
			JdbcUtils.closeStatement(ps);
			JdbcUtils.closeConnection(conn);
		}
	}

	public void blockUser(AuthenticationToken token) throws BlockedException {
		blockUser(token, dataSource);
	}

	public Integer getNumberRetrieValue() {
		return numberRetrieValue;
	}

	public void setNumberRetrieValue(Integer numberRetrieValue) {
		this.numberRetrieValue = numberRetrieValue;
	}

	public void logSucess(AuthenticationToken token, TimeZone timezone) throws LogAuthException {
		log(token, timezone, true);
	}

	public void logUnSucess(AuthenticationToken token, TimeZone timezone) throws LogAuthException {
		log(token, timezone, false);
		if (excedLimit(token)) {
			blockUser(token, dataSource);
		}
	}

	private void log(AuthenticationToken token, TimeZone timezone, boolean sucess) throws LogAuthException {
		Connection conn = null;
		PreparedStatement ps = null;
		try {
			String username = getUsername(token);

			conn = dataSource.getConnection();
			ps = conn.prepareStatement(logQuery);
			ps.setString(1, username);
			ps.setString(2, UtilSecurity.getDateNow());
			ps.setString(3, timezone.getID());
			ps.setBoolean(4, sucess);
			ps.executeUpdate();
		} catch (Exception e) {
			throw new LogAuthException("erro ao registrar acesso do usuario", e);
		} finally {
			JdbcUtils.closeStatement(ps);
			JdbcUtils.closeConnection(conn);
		}
	}

	public boolean excedLimit(AuthenticationToken token) throws LogAuthException {
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String username = getUsername(token);
			conn = dataSource.getConnection();
			ps = conn.prepareStatement(successLogQuery);
			ps.setString(1, username);
			ps.setInt(2, numberRetrieValue);
			rs = ps.executeQuery();
			int unsucess = 0;
			while (rs.next()) {
				boolean value = rs.getBoolean(1);
				if (!value) {
					unsucess = unsucess + 1;
				}
			}
			if (unsucess >= numberRetrieValue) {
				return true;
			}
			return false;
		} catch (Exception e) {
			throw new LogAuthException("erro ao registrar acesso do usuario", e);
		} finally {
			JdbcUtils.closeResultSet(rs);
			JdbcUtils.closeStatement(ps);
			JdbcUtils.closeConnection(conn);
		}
	}

	public String getBlockQuery() {
		return blockQuery;
	}

	public void setBlockQuery(String blockQuery) {
		this.blockQuery = blockQuery;
	}

	public String getLogQuery() {
		return logQuery;
	}

	public void setLogQuery(String logQuery) {
		this.logQuery = logQuery;
	}

	public String getSuccessLogQuery() {
		return successLogQuery;
	}

	public void setSuccessLogQuery(String successLogQuery) {
		this.successLogQuery = successLogQuery;
	}

	public InfoAuthc getAuthSucess(AuthenticationToken token) {
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String username = getUsername(token);
			conn = dataSource.getConnection();
			ps = conn.prepareStatement(sucessLoginQuery);
			ps.setString(1, username);
			rs = ps.executeQuery();
			InfoAuthc infoAuthc = new InfoAuthc();
			if (rs.next()) {
				infoAuthc.setDataAuthc(rs.getString(1));
				infoAuthc.setTimezone(rs.getString(2));
			}
			return infoAuthc;
		} catch (Exception e) {
			log.error("Não foi possível verificar a última autenticação", e);
		} finally {
			JdbcUtils.closeResultSet(rs);
			JdbcUtils.closeStatement(ps);
			JdbcUtils.closeConnection(conn);
		}
		return null;
	}

	public boolean alterPassword(AuthenticationToken token, Integer limitDays) {

		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String username = getUsername(token);
			conn = dataSource.getConnection();
			ps = conn.prepareStatement(updateLoginQuery);
			ps.setString(1, username);
			rs = ps.executeQuery();
			if (rs.next()) {
				Calendar calendar = Calendar.getInstance();
				calendar.add(Calendar.DAY_OF_YEAR, limitDays * -1);
				Timestamp timeStamp = rs.getTimestamp(1);
				if (calendar.getTime().compareTo(timeStamp) > 0) {
					return true;
				}
			}
			return false;
		} catch (Exception e) {
			log.error("Não foi possível verificar a data do último login", e);
		} finally {
			JdbcUtils.closeResultSet(rs);
			JdbcUtils.closeStatement(ps);
			JdbcUtils.closeConnection(conn);
		}
		return false;
	}

	public void updatePassword(String username, String password) throws PasswordException {

		Connection conn = null;
		PreparedStatement ps = null;

		try {
			java.util.Date date = new java.util.Date();
			Timestamp time = new Timestamp(date.getTime());
			conn = dataSource.getConnection();
			isEqualLastPassword(username, password, conn);
			password = UtilPassword.genPassword(password);
			ps = conn.prepareStatement(updatePasswordQuery);
			ps.setString(1, password);
			ps.setTimestamp(2, time);
			ps.setString(3, username);
			ps.executeUpdate();

		} catch (SQLException e) {
			log.error(e.getMessage());
			throw new PasswordException("Não foi possível alterar a senha. Contate administrador.", e);
		} finally {
			JdbcUtils.closeStatement(ps);
			JdbcUtils.closeConnection(conn);
		}
	}

	public void isEqualLastPassword(String username, String passwordText, Connection conn) throws PasswordException {

		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			ps = conn.prepareStatement(authenticationQuery);
			ps.setString(1, username);

			rs = ps.executeQuery();
			if (rs.next()) {
				String passwordSaved = rs.getString(1);
				if (UtilPassword.comparePassword(passwordText, passwordSaved)) {
					throw new PasswordException("A senha deve ser diferente da última senha salva.");
				}
			}

		} catch (SQLException e) {
			log.error(e.getMessage());
			throw new PasswordException("Não foi possível validar a senha. Contate administrador.", e);
		} finally {
			JdbcUtils.closeResultSet(rs);
			JdbcUtils.closeStatement(ps);

		}
	}

	public List<InfoAuthc> getAuthFail(AuthenticationToken token) {
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			String username = getUsername(token);
			conn = dataSource.getConnection();
			ps = conn.prepareStatement(failLoginQuery);
			ps.setString(1, username);
			ps.setInt(2, failLoginLimit);
			rs = ps.executeQuery();
			List<InfoAuthc> infoAuthcList = new ArrayList<InfoAuthc>();
			while (rs.next()) {
				InfoAuthc infoAuthc = new InfoAuthc();
				infoAuthc.setDataAuthc(rs.getString(1));
				infoAuthc.setTimezone(rs.getString(2));
				infoAuthcList.add(infoAuthc);
			}
			return infoAuthcList;
		} catch (Exception e) {
			log.error("Não foi possível verificar as tentativas de login que falharam.", e);
		} finally {
			JdbcUtils.closeResultSet(rs);
			JdbcUtils.closeStatement(ps);
			JdbcUtils.closeConnection(conn);
		}
		return null;
	}

	public String getFailLoginQuery() {
		return failLoginQuery;
	}

	public void setFailLoginQuery(String failLoginQuery) {
		this.failLoginQuery = failLoginQuery;
	}

	public String getSucessLoginQuery() {
		return sucessLoginQuery;
	}

	public void setSucessLoginQuery(String sucessLoginQuery) {
		this.sucessLoginQuery = sucessLoginQuery;
	}

	public String getUpdateLoginQuery() {
		return updateLoginQuery;
	}

	public void setUpdateLoginQuery(String updateLoginQuery) {
		this.updateLoginQuery = updateLoginQuery;
	}

	public String getUpdatePasswordQuery() {
		return updatePasswordQuery;
	}

	public void setUpdatePasswordQuery(String updatePasswordQuery) {
		this.updatePasswordQuery = updatePasswordQuery;
	}

	public FormAuthenticationFilter getFormAuthenticationFilter() {
		return formAuthenticationFilter;
	}

	public void setFormAuthenticationFilter(FormAuthenticationFilter formAuthenticationFilter) {
		this.formAuthenticationFilter = formAuthenticationFilter;
	}

	public String getSucessUrlCuidador() {
		return sucessUrlCuidador;
	}

	public void setSucessUrlCuidador(String sucessUrlCuidador) {
		this.sucessUrlCuidador = sucessUrlCuidador;
	}

	public String getSucessUrlresp() {
		return sucessUrlresp;
	}

	public void setSucessUrlresp(String sucessUrlresp) {
		this.sucessUrlresp = sucessUrlresp;
	}
	
	

}
