package eu.europa.esig.dss.jaxb.parsers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import eu.europa.esig.dss.enumerations.EndorsementType;

public class EndorsementTypeParserTest {

	@Test
	public void printAndParse() {
		for (EndorsementType type : EndorsementType.values()) {
			assertEquals(type, EndorsementTypeParser.parse(EndorsementTypeParser.print(type)));
		}
	}

	@Test
	public void unknow() {
		assertNull(EndorsementTypeParser.parse("bla"));
		assertNull(EndorsementTypeParser.print(null));
	}

}
