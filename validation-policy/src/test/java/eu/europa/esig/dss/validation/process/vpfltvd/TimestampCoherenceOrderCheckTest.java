package eu.europa.esig.dss.validation.process.vpfltvd;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampCoherenceOrderCheck;

public class TimestampCoherenceOrderCheckTest extends AbstractTestCheck {
	
	private LevelConstraint constraint;
	private XmlValidationProcessLongTermData result;
	
	@BeforeEach
	public void initialize() {
		constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		result = new XmlValidationProcessLongTermData();
	}
	
	@Test
	public void validOrderCheckTest() throws Exception {
		List<TimestampWrapper> timestamps = new ArrayList<>();
		timestamps.add(getTimestampWrapper("T-1", new Date(), TimestampType.CONTENT_TIMESTAMP));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-2", new Date(), TimestampType.SIGNATURE_TIMESTAMP, "T-1"));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-3", new Date(), TimestampType.VALIDATION_DATA_TIMESTAMP));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-4", new Date(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3"));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-5", new Date(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3", "T-4"));
		
		validate(timestamps, XmlStatus.OK);
	}
	
	@Test
	public void sameTimeCheckTest() throws Exception {
		List<TimestampWrapper> timestamps = new ArrayList<>();
		Date productionTime = new Date();
		timestamps.add(getTimestampWrapper("T-1", productionTime, TimestampType.CONTENT_TIMESTAMP));
		timestamps.add(getTimestampWrapper("T-2", productionTime, TimestampType.SIGNATURE_TIMESTAMP, "T-1"));
		timestamps.add(getTimestampWrapper("T-3", productionTime, TimestampType.VALIDATION_DATA_TIMESTAMP));
		timestamps.add(getTimestampWrapper("T-4", productionTime, TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3"));
		timestamps.add(getTimestampWrapper("T-5", productionTime, TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3", "T-4"));
		
		validate(timestamps, XmlStatus.OK);
	}
	
	@Test
	public void contentTstsCheckTest() throws Exception {
		List<TimestampWrapper> timestamps = new ArrayList<>();
		timestamps.add(getTimestampWrapper("T-1", new Date(), TimestampType.CONTENT_TIMESTAMP));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-2", new Date(), TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-3", new Date(), TimestampType.ALL_DATA_OBJECTS_TIMESTAMP));
		
		validate(timestamps, XmlStatus.OK);
	}
	
	@Test
	public void separatedSignatureAndArchiveTimestampsTest() throws Exception {
		List<TimestampWrapper> timestamps = new ArrayList<>();
		timestamps.add(getTimestampWrapper("T-1", new Date(), TimestampType.CONTENT_TIMESTAMP));
		Thread.sleep(1);
		Date productionTime = new Date();
		timestamps.add(getTimestampWrapper("T-2-1", productionTime, TimestampType.SIGNATURE_TIMESTAMP, "T-1"));
		timestamps.add(getTimestampWrapper("T-2-2", productionTime, TimestampType.SIGNATURE_TIMESTAMP, "T-2"));
		Thread.sleep(1);
		productionTime = new Date();
		timestamps.add(getTimestampWrapper("T-3-1", productionTime, TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2-1"));
		timestamps.add(getTimestampWrapper("T-3-2", productionTime, TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2-2"));
		
		validate(timestamps, XmlStatus.OK);
	}
	
	@Test
	public void separatedSignatureAndArchiveTimestampsDifferentTimeTest() throws Exception {
		List<TimestampWrapper> timestamps = new ArrayList<>();
		timestamps.add(getTimestampWrapper("T-a", new Date(), TimestampType.CONTENT_TIMESTAMP));
		timestamps.add(getTimestampWrapper("T-b", new Date(), TimestampType.CONTENT_TIMESTAMP));
		Thread.sleep(1);
		Date productionTime = new Date();
		timestamps.add(getTimestampWrapper("T-2-1", productionTime, TimestampType.SIGNATURE_TIMESTAMP, "T-a"));
		timestamps.add(getTimestampWrapper("T-2-2", productionTime, TimestampType.SIGNATURE_TIMESTAMP, "T-a", "T-b"));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-3-1", new Date(), TimestampType.ARCHIVE_TIMESTAMP, "T-a", "T-2-1"));
		timestamps.add(getTimestampWrapper("T-3-2", productionTime, TimestampType.ARCHIVE_TIMESTAMP, "T-a", "T-b", "T-2-2"));
		
		validate(timestamps, XmlStatus.OK);
	}
	
	@Test
	public void typeOrderFailCheckTest() throws Exception {
		List<TimestampWrapper> timestamps = new ArrayList<>();
		timestamps.add(getTimestampWrapper("T-1", new Date(), TimestampType.SIGNATURE_TIMESTAMP));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-2", new Date(), TimestampType.CONTENT_TIMESTAMP));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-3", new Date(), TimestampType.VALIDATION_DATA_TIMESTAMP));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-4", new Date(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3"));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-5", new Date(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3", "T-4"));
		
		validate(timestamps, XmlStatus.NOT_OK);
	}
	
	@Test
	public void timeOrderFailCheckTest() throws Exception {
		List<TimestampWrapper> timestamps = new ArrayList<>();
		Date productionTime = new Date();
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-1", new Date(), TimestampType.CONTENT_TIMESTAMP));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-2", new Date(), TimestampType.SIGNATURE_TIMESTAMP, "T-1"));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-3", new Date(), TimestampType.VALIDATION_DATA_TIMESTAMP));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-4", new Date(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3"));
		timestamps.add(getTimestampWrapper("T-5", productionTime, TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3", "T-4"));
		
		validate(timestamps, XmlStatus.NOT_OK);
	}
	
	@Test
	public void refOrderFailCheckTest() throws Exception {
		List<TimestampWrapper> timestamps = new ArrayList<>();
		timestamps.add(getTimestampWrapper("T-1", new Date(), TimestampType.CONTENT_TIMESTAMP));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-2", new Date(), TimestampType.SIGNATURE_TIMESTAMP, "T-1"));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-3", new Date(), TimestampType.VALIDATION_DATA_TIMESTAMP));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-4", new Date(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3", "T-5"));
		Thread.sleep(1);
		timestamps.add(getTimestampWrapper("T-5", new Date(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3"));
		
		validate(timestamps, XmlStatus.NOT_OK);
	}
	
	private void validate(List<TimestampWrapper> timestamps, XmlStatus expectedResult) {
		TimestampCoherenceOrderCheck tcoc = new TimestampCoherenceOrderCheck(i18nProvider, result, timestamps,
				constraint);
		tcoc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(expectedResult, constraints.get(0).getStatus());
	}
	
	private TimestampWrapper getTimestampWrapper(String id, Date productionTime, TimestampType type, String... coveredTimestamps) {
		XmlTimestamp xmlTimestamp = new XmlTimestamp();
		xmlTimestamp.setId(id);
		xmlTimestamp.setProductionTime(productionTime);
		xmlTimestamp.setType(type);
		List<XmlTimestampedObject> timestampedObjects = new ArrayList<>();
		for (String timestampId : coveredTimestamps) {
			XmlTimestampedObject xmlTimestampedObject = new XmlTimestampedObject();
			XmlTimestamp coveredXmlTimestamp = new XmlTimestamp();
			coveredXmlTimestamp.setId(timestampId);
			xmlTimestampedObject.setToken(coveredXmlTimestamp);
			xmlTimestampedObject.setCategory(TimestampedObjectType.TIMESTAMP);
			timestampedObjects.add(xmlTimestampedObject);
		}
		xmlTimestamp.setTimestampedObjects(timestampedObjects);
		return new TimestampWrapper(xmlTimestamp);
	}

}
