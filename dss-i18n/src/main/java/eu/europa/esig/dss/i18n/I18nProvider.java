package eu.europa.esig.dss.i18n;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Internalization provider
 *
 */
public class I18nProvider {

	private static final Logger LOG = LoggerFactory.getLogger(I18nProvider.class);
	
	private static final String MESSAGES = "dss-messages"; // defined a name of the target file
	
	// Use system locale as default
	private final ResourceBundle bundle;
	
	// a set of possible keys
	private final Set<String> keySet;
	
	/**
	 * Default internationalization constructor
	 * Instantiates a default {@code Locale}
	 */
	public I18nProvider() {
		this(Locale.getDefault());
	}
	
	/**
	 * Returns an instance of {@code I18nProvider}
	 * 
	 * @param locale {@link Locale} language/location to use
	 */
	public I18nProvider(Locale locale) {
		this.bundle = ResourceBundle.getBundle(MESSAGES, locale);
		this.keySet = bundle.keySet();
	}
	
	/**
	 * Extracts an {@code I18nMessage} by its key
	 * 
	 * @param messageTag {@link MessageTag} key of the message to get value for
	 * @return {@link String} message value
	 */
	public String getMessage(MessageTag messageTag) {
		if (messageTag == null) {
			throw new IllegalArgumentException("messageTag cannot be null!");
			
		} else if (keySet.contains(messageTag.getId())) {
			String patternString = bundle.getString(messageTag.getId());
			return MessageFormat.format(patternString, messageTag.getArgs());
			
		} else {
			// in case if a value for the message tage does not exist
			LOG.warn("A value for the MessageTag [{}] not defined!", messageTag.getId());
			return messageTag.getId();
		}
	}
	
}
