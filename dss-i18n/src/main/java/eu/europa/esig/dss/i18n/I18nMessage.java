package eu.europa.esig.dss.i18n;

public class I18nMessage {
	
	private final String key;
	private final String value;
	
	public I18nMessage(final String key, final String value) {
		this.key = key;
		this.value = value;
	}
	
	public String getKey() {
		return key;
	}
	
	public String getValue() {
		return value;
	}

}
