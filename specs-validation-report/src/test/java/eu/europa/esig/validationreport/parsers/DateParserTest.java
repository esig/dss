package eu.europa.esig.validationreport.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Date;

import org.junit.jupiter.api.Test;

import eu.europa.esig.validationreport.parsers.DateParser;

public class DateParserTest {

	@Test
	public void testValid() {
		String validDateString = "2015-07-05T22:00:00Z";
		Date date = DateParser.parse(validDateString);
		assertNotNull(date);
		String print = DateParser.print(date);
		assertEquals(validDateString, print);

		String printNewDate = DateParser.print(new Date());
		assertNotNull(printNewDate);
	}

	@Test
	public void testInvalid() {
		String invalidDateString = "aaa";
		Date date = DateParser.parse(invalidDateString);
		assertNull(date);
	}

}
