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
	private final ResourceBundle bundle;
	
	// a set of possible keys
	private final Set<String> keySet;
	
	/**
	 * Returns an instance of {@code I18nProvider}
	 * 
	 * @param locale {@link Locale} language/location to use
	 * @return {@link I18nProvider}
	 */
	public I18nProvider(Locale locale) {
		this.bundle = ResourceBundle.getBundle(MESSAGES, locale);
		this.keySet = bundle.keySet();
	}
	
	/**
	 * Extracts an {@code I18nMessage} by its key
	 * 
	 * @param key {@link String} key of the message to get value for
	 * @return {@link I18nMessage}
	 */
	public String getMessage(MessageTag messageTag) {
		if (messageTag != null && keySet.contains(messageTag.getId())) {
			return bundle.getString(messageTag.getId());
		}
		return null;
	}
	

}
