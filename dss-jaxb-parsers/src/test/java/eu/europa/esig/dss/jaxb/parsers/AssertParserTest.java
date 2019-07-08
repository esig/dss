package eu.europa.esig.dss.jaxb.parsers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import eu.europa.esig.dss.enumerations.Assert;

public class AssertParserTest {

	@Test
	public void testEnum() {
		for (Assert a : Assert.values()) {
			String string = AssertParser.print(a);
			assertNotNull(string);
			Assert parse = AssertParser.parse(string);
			assertEquals(a, parse);
		}
	}

	@Test
	public void parseUnknown() {
		assertNull(AssertParser.parse("bla"));
	}

}
