package eu.europa.esig.dss.jaxb.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.SignatureLevel;

public class SignatureFormatParserTest {

	@Test
	public void testEnum() {
		for (SignatureLevel sLevel : SignatureLevel.values()) {
			String string = SignatureFormatParser.print(sLevel);
			assertNotNull(string);
			SignatureLevel parse = SignatureFormatParser.parse(string);
			assertEquals(sLevel, parse);
		}
	}

	@Test
	public void parseUnknown() {
		Exception exception = assertThrows(IllegalArgumentException.class, () -> {
			SignatureFormatParser.parse("non-value");
		});
		assertEquals("No enum constant eu.europa.esig.dss.enumerations.SignatureLevel.non_value", exception.getMessage());
	}

}
