package eu.europa.esig.dss.jaxb.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;

public class ObjectIdentifierQualifierParserTest {

	@Test
	public void testEnum() {
		for (ObjectIdentifierQualifier qualifier : ObjectIdentifierQualifier.values()) {
			String string = ObjectIdentifierQualifierParser.print(qualifier);
			assertNotNull(string);
			ObjectIdentifierQualifier parse = ObjectIdentifierQualifierParser.parse(string);
			assertEquals(qualifier, parse);
		}
	}

	@Test
	public void parseUnknown() {
		assertThrows(IllegalArgumentException.class, () -> {
			assertNull(ObjectIdentifierQualifierParser.parse("bla"));
		});
	}

}
