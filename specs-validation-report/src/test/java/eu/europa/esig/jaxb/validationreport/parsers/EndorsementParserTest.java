package eu.europa.esig.jaxb.validationreport.parsers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import eu.europa.esig.jaxb.validationreport.enums.EndorsementType;
import eu.europa.esig.jaxb.validationreport.parsers.EndorsementParser;

public class EndorsementParserTest {

	@Test
	public void printAndParse() {
		for (EndorsementType type : EndorsementType.values()) {
			assertEquals(type, EndorsementParser.parse(EndorsementParser.print(type)));
		}
	}

	@Test
	public void unknow() {
		assertNull(EndorsementParser.parse("bla"));
		assertNull(EndorsementParser.print(null));
	}

}
