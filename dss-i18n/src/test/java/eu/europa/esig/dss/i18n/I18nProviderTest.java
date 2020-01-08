package eu.europa.esig.dss.i18n;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Locale;

import org.junit.jupiter.api.Test;

public class I18nProviderTest {
	
	@Test
	public void test() {
		
		final I18nProvider i18nProvider = new I18nProvider(Locale.ENGLISH);
		
		String message = i18nProvider.getMessage(MessageTag.BBB_XCV_CCCBB);
		assertNotNull(message);
		assertEquals("Can the certificate chain be built till a trust anchor?", message);
		
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> { i18nProvider.getMessage(null); });
		assertEquals("messageTag cannot be null!", exception.getMessage());
		
		final I18nProvider i18nFranceProvider = new I18nProvider(Locale.FRANCE);
		message = i18nFranceProvider.getMessage(MessageTag.BBB_XCV_CCCBB);
		assertNotNull(message);
		assertEquals("Peut-on remonter jusqu'\u00E0 une ancre de confiance ?", message);
		
		final I18nProvider i18nFrenchProvider = new I18nProvider(Locale.FRENCH);
		message = i18nFrenchProvider.getMessage(MessageTag.BBB_XCV_CCCBB);
		assertNotNull(message);
		assertEquals("Peut-on remonter jusqu'\u00E0 une ancre de confiance ?", message);

		final I18nProvider i18nGermanProvider = new I18nProvider(Locale.GERMAN);
		message = i18nGermanProvider.getMessage(MessageTag.BBB_XCV_CCCBB);
		assertNotNull(message);
		assertEquals("Can the certificate chain be built till a trust anchor?", message);
		
	}

}
