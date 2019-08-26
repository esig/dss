package eu.europa.esig.dss.jaxb.parsers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

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

	@Test(expected = IllegalArgumentException.class)
	public void parseUnknown() {
		SignatureFormatParser.parse("non-value");
	}

}
