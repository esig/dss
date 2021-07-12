/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.jaxb.parsers;

import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;


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
		assertThrows(IllegalArgumentException.class, () -> DateParser.parse(invalidDateString));
	}

	@Test
	public void testNull() {
		assertNull(DateParser.parse(null));
		assertNull(DateParser.print(null));
	}

}
