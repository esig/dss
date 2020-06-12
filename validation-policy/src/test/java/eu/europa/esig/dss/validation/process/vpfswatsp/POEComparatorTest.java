package eu.europa.esig.dss.validation.process.vpfswatsp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampType;

public class POEComparatorTest {
	
	@Test
	public void test() throws Exception {
		POEComparator comparator = new POEComparator();
		
		Date currentTime = new Date();
		POE currentTimePoe = new POE(currentTime);
		
		XmlTimestamp xmlTimestamp = new XmlTimestamp();
		xmlTimestamp.setType(TimestampType.CONTENT_TIMESTAMP);
		xmlTimestamp.setProductionTime(currentTime);
		TimestampWrapper firstTimestamp = new TimestampWrapper(xmlTimestamp);
		
		assertFalse(comparator.before(currentTimePoe, new POE(firstTimestamp)));
		assertTrue(comparator.before(new POE(firstTimestamp), currentTimePoe));
		
		XmlTimestamp xmlTimestamp2 = new XmlTimestamp();
		xmlTimestamp2.setType(TimestampType.SIGNATURE_TIMESTAMP);
		xmlTimestamp2.setProductionTime(currentTime);
		TimestampWrapper secondTimestamp = new TimestampWrapper(xmlTimestamp2);
		assertTrue(comparator.before(new POE(firstTimestamp), new POE(secondTimestamp)));
		
		Thread.sleep(10); // to be sure in different Date()
		
		xmlTimestamp.setProductionTime(new Date());
		assertFalse(comparator.before(new POE(firstTimestamp), new POE(secondTimestamp)));
		assertTrue(comparator.before(new POE(secondTimestamp), new POE(firstTimestamp)));
		
		xmlTimestamp.setType(TimestampType.ARCHIVE_TIMESTAMP);
		xmlTimestamp2.setType(TimestampType.ARCHIVE_TIMESTAMP);
		xmlTimestamp2.setProductionTime(xmlTimestamp.getProductionTime());
		
		assertFalse(comparator.before(new POE(firstTimestamp), new POE(secondTimestamp)));
		assertFalse(comparator.before(new POE(secondTimestamp), new POE(firstTimestamp)));
		assertEquals(0, comparator.compare(new POE(firstTimestamp), new POE(secondTimestamp)));
		
		xmlTimestamp.setTimestampedObjects(new ArrayList<>());
		xmlTimestamp2.setTimestampedObjects(Arrays.asList(new XmlTimestampedObject()));
		
		assertTrue(comparator.before(new POE(firstTimestamp), new POE(secondTimestamp)));
		assertFalse(comparator.before(new POE(secondTimestamp), new POE(firstTimestamp)));
		assertNotEquals(0, comparator.compare(new POE(firstTimestamp), new POE(secondTimestamp)));
		
		xmlTimestamp2.setType(TimestampType.VALIDATION_DATA_TIMESTAMP);
		assertFalse(comparator.before(new POE(firstTimestamp), new POE(secondTimestamp)));
		assertTrue(comparator.before(new POE(secondTimestamp), new POE(firstTimestamp)));
		
	}
	
	@Test
	public void nullPointerTest() {
		Exception exception = assertThrows(NullPointerException.class, () -> new POE((Date) null));
		assertEquals("The controlTime must be defined!", exception.getMessage());
		exception = assertThrows(NullPointerException.class, () -> new POE((TimestampWrapper) null));
		assertEquals("The timestampWrapper must be defined!", exception.getMessage());
	}

}
