package eu.europa.esig.dss.i18n;

import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;

/**
 * Internalization provider
 *
 */
public class I18nProvider {
	
	private static final String MESSAGES = "Messages"; // defined a name of the target file
	
	// Use system locale as default
	private ResourceBundle bundle = getResourceBundle(Locale.getDefault());
	private Set<String> keySet;
	
	private static I18nProvider i18nProvider;
	
	private I18nProvider() {
	}
	
	/**
	 * Returns an instance of {@code I18nProvider}
	 * 
	 * @return {@link I18nProvider}
	 */
	public static I18nProvider getInstance() {
		if (i18nProvider == null) {
			i18nProvider = new I18nProvider();
		}
		return i18nProvider;
	}
	
	/**
	 * Allows to configure a language to be used in the validation reports
	 * NOTE: if not set, the default value is used
	 * 
	 * @param locale {@link Locale}
	 */
	public void setLocale(Locale locale) {
		bundle = getResourceBundle(locale);
	}
	
	private ResourceBundle getResourceBundle(Locale locale) {
		return ResourceBundle.getBundle(MESSAGES, locale);
	}
	
	private Set<String> getKeySet() {
		if (keySet == null) {
			keySet = bundle.keySet();
		}
		return keySet;
	}
	
	/**
	 * Extracts an {@code I18nMessage} by its key
	 * 
	 * @param key {@link String} key of the message to get value for
	 * @return {@link I18nMessage}
	 */
	public I18nMessage getMessage(String key) {
		if (getKeySet().contains(key)) {
			return new I18nMessage(key, bundle.getString(key));
		}
		return null;
	}
	

}
