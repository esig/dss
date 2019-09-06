package eu.europa.esig.dss.jaxb.parsers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.jaxb.parsers.KeyUsageBitParser;

public class KeyUsageBitParserTest {

	@Test
	public void testEnum() {
		for (KeyUsageBit kub : KeyUsageBit.values()) {
			String string = KeyUsageBitParser.print(kub);
			assertNotNull(string);
			KeyUsageBit parse = KeyUsageBitParser.parse(string);
			assertEquals(kub, parse);
		}
	}

	@Test
	public void parseUnknown() {
		assertNull(KeyUsageBitParser.parse("bla"));
	}

}
