package eu.europa.esig.dss.i18n;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class MessageTagTest {
	
	private static I18nProvider i18nProvider;
	
	@BeforeAll
	public static void init() {
		i18nProvider = new I18nProvider();
	}
	
	@Test
	public void allMessagesPresent() {
		MessageTag[] values = MessageTag.values();
		assertNotNull(values);
		assertTrue(values.length > 0);
		
		for (MessageTag messageTag : values) {
			String message = i18nProvider.getMessage(messageTag);
			assertNotNull(message, "A message property for a MessageTag with id [" + messageTag.getId() + "] is not defined!");
		}
	}
	
	@Test
	public void allFRMessagesPresent() {
		MessageTag[] values = MessageTag.values();
		assertNotNull(values);
		assertTrue(values.length > 0);
		
		// all messages that are not defined in the language-related messages_*.properties
		// will be overridden by default values
		I18nProvider i18nFRProvider = new I18nProvider(Locale.FRENCH);
		for (MessageTag messageTag : values) {
			String message = i18nFRProvider.getMessage(messageTag);
			assertNotNull(message, "A message property for a MessageTag with id [" + messageTag.getId() + "] is not defined!");
		}
	}
	
	@Test
	public void allMessageTagsPresent() {
		ResourceBundle bundle = ResourceBundle.getBundle("dss-messages", Locale.getDefault());
		Set<String> keySet = bundle.keySet();
		assertNotNull(keySet);
		assertTrue(keySet.size() > 0);
		
		MessageTag[] messageTags = MessageTag.values();
		for (String key : keySet) {
			assertTrue(Arrays.stream(messageTags).anyMatch(tag -> tag.getId().equals(key)), "MessageTag with a key [" + key + "] does not exist!");
		}
	}

}
