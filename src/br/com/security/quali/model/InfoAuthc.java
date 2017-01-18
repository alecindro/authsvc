package br.com.security.quali.model;

import java.io.Serializable;

public class InfoAuthc implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String dataAuthc;
	private String timezone;
	public String getDataAuthc() {
		return dataAuthc;
	}
	public void setDataAuthc(String dataAuthc) {
		this.dataAuthc = dataAuthc;
	}
	public String getTimezone() {
		return timezone;
	}
	public void setTimezone(String timezone) {
		this.timezone = timezone;
	}
	
	
	
	
}
