package eu.europa.esig.dss.i18n;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Locale;

import org.junit.jupiter.api.Test;

public class I18nProviderTest {
	
	private static final String BBB_XCV_SUB = "BBB_XCV_SUB";
	
	@Test
	public void test() {
		
		I18nProvider i18nProvider = I18nProvider.getInstance();
		i18nProvider.setLocale(Locale.getDefault());
		
		I18nMessage message = i18nProvider.getMessage(BBB_XCV_SUB);
		assertNotNull(message);
		assertEquals(BBB_XCV_SUB, message.getKey());
		assertEquals("Is the certificate validation conclusive?", message.getValue());
		
		message = i18nProvider.getMessage("DOES_NOT_EXIST");
		assertNull(message);
		
		i18nProvider.setLocale(Locale.FRANCE);
		message = i18nProvider.getMessage(BBB_XCV_SUB);
		assertNotNull(message);
		assertEquals(BBB_XCV_SUB, message.getKey());
		assertEquals("La validation du certificat est-elle concluante?", message.getValue());
		
		i18nProvider.setLocale(Locale.GERMAN);
		message = i18nProvider.getMessage(BBB_XCV_SUB);
		assertNotNull(message);
		assertEquals(BBB_XCV_SUB, message.getKey());
		assertEquals("Is the certificate validation conclusive?", message.getValue());
		
	}

}
