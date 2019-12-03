package eu.europa.esig.dss.i18n;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Locale;

import org.junit.jupiter.api.Test;

public class I18nProviderTest {
	
	@Test
	public void test() {
		
		I18nProvider i18nProvider = new I18nProvider(Locale.getDefault());
		
		String message = i18nProvider.getMessage(MessageTag.BBB_XCV_SUB);
		assertNotNull(message);
		assertEquals("Is the certificate validation conclusive?", message);
		
		message = i18nProvider.getMessage(null);
		assertNull(message);
		
		i18nProvider = new I18nProvider(Locale.FRANCE);
		message = i18nProvider.getMessage(MessageTag.BBB_XCV_SUB);
		assertNotNull(message);
		assertEquals("La validation du certificat est-elle concluante?", message);

		i18nProvider = new I18nProvider(Locale.GERMAN);
		message = i18nProvider.getMessage(MessageTag.BBB_XCV_SUB);
		assertNotNull(message);
		assertEquals("Is the certificate validation conclusive?", message);
		
	}

}
