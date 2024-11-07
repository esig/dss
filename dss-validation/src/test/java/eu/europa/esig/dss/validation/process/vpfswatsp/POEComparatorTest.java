/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.process.vpfswatsp;

import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampType;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class POEComparatorTest {
	
	@Test
	void test() {
		POEComparator comparator = new POEComparator();
		
		Calendar calendar = Calendar.getInstance();

		Date currentTime = calendar.getTime();
		POE currentTimePoe = new POE(currentTime);
		
		XmlTimestamp xmlTimestamp = new XmlTimestamp();
		xmlTimestamp.setType(TimestampType.CONTENT_TIMESTAMP);
		xmlTimestamp.setProductionTime(currentTime);
		TimestampWrapper firstTimestamp = new TimestampWrapper(xmlTimestamp);
		
		assertFalse(comparator.before(currentTimePoe, new TimestampPOE(firstTimestamp)));
		assertTrue(comparator.before(new TimestampPOE(firstTimestamp), currentTimePoe));
		
		XmlTimestamp xmlTimestamp2 = new XmlTimestamp();
		xmlTimestamp2.setType(TimestampType.SIGNATURE_TIMESTAMP);
		xmlTimestamp2.setProductionTime(currentTime);
		TimestampWrapper secondTimestamp = new TimestampWrapper(xmlTimestamp2);
		assertTrue(comparator.before(new TimestampPOE(firstTimestamp), new TimestampPOE(secondTimestamp)));
		
		calendar.add(Calendar.SECOND, 1);
		xmlTimestamp.setProductionTime(calendar.getTime());
		assertFalse(comparator.before(new TimestampPOE(firstTimestamp), new TimestampPOE(secondTimestamp)));
		assertTrue(comparator.before(new TimestampPOE(secondTimestamp), new TimestampPOE(firstTimestamp)));
		
		xmlTimestamp.setType(TimestampType.ARCHIVE_TIMESTAMP);
		xmlTimestamp2.setType(TimestampType.ARCHIVE_TIMESTAMP);
		xmlTimestamp2.setProductionTime(xmlTimestamp.getProductionTime());
		
		assertFalse(comparator.before(new TimestampPOE(firstTimestamp), new TimestampPOE(secondTimestamp)));
		assertFalse(comparator.before(new TimestampPOE(secondTimestamp), new TimestampPOE(firstTimestamp)));
		assertEquals(0, comparator.compare(new TimestampPOE(firstTimestamp), new TimestampPOE(secondTimestamp)));
		
		xmlTimestamp.setTimestampedObjects(new ArrayList<>());
		xmlTimestamp2.setTimestampedObjects(Arrays.asList(new XmlTimestampedObject()));
		
		assertTrue(comparator.before(new TimestampPOE(firstTimestamp), new TimestampPOE(secondTimestamp)));
		assertFalse(comparator.before(new TimestampPOE(secondTimestamp), new TimestampPOE(firstTimestamp)));
		assertNotEquals(0, comparator.compare(new TimestampPOE(firstTimestamp), new TimestampPOE(secondTimestamp)));
		
		xmlTimestamp2.setType(TimestampType.VALIDATION_DATA_TIMESTAMP);
		assertFalse(comparator.before(new TimestampPOE(firstTimestamp), new TimestampPOE(secondTimestamp)));
		assertTrue(comparator.before(new TimestampPOE(secondTimestamp), new TimestampPOE(firstTimestamp)));
		
	}
	
	@Test
	void nullPointerTest() {
		Exception exception = assertThrows(NullPointerException.class, () -> new POE(null));
		assertEquals("The controlTime must be defined!", exception.getMessage());
		exception = assertThrows(NullPointerException.class, () -> new TimestampPOE(null));
		assertEquals("The timestampWrapper must be defined!", exception.getMessage());
	}

}
