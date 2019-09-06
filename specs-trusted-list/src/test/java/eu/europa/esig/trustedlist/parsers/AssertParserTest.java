package eu.europa.esig.trustedlist.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

import eu.europa.esig.trustedlist.enums.Assert;
import eu.europa.esig.trustedlist.parsers.AssertParser;

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
