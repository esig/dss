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
package eu.europa.esig.dss.validation.process.vpfltvd;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.vpfltvd.checks.TimestampCoherenceOrderCheck;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class TimestampCoherenceOrderCheckTest extends AbstractTestCheck {
	
	private LevelConstraint constraint;
	private XmlValidationProcessLongTermData result;
	
	@BeforeEach
	void initialize() {
		constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		result = new XmlValidationProcessLongTermData();
	}
	
	@Test
	void validOrderCheckTest() {
		Calendar calendar = Calendar.getInstance();

		List<TimestampWrapper> timestamps = new ArrayList<>();
		timestamps.add(getTimestampWrapper("T-1", calendar.getTime(), TimestampType.CONTENT_TIMESTAMP));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-2", calendar.getTime(), TimestampType.SIGNATURE_TIMESTAMP, "T-1"));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-3", calendar.getTime(), TimestampType.VALIDATION_DATA_TIMESTAMP));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-4", calendar.getTime(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3"));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-5", calendar.getTime(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3", "T-4"));
		
		validate(timestamps, XmlStatus.OK);
	}
	
	@Test
	void sameTimeCheckTest() {
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
	void contentTstsCheckTest() {

		Calendar calendar = Calendar.getInstance();

		List<TimestampWrapper> timestamps = new ArrayList<>();
		timestamps.add(getTimestampWrapper("T-1", calendar.getTime(), TimestampType.CONTENT_TIMESTAMP));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-2", calendar.getTime(), TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-3", calendar.getTime(), TimestampType.ALL_DATA_OBJECTS_TIMESTAMP));
		
		validate(timestamps, XmlStatus.OK);
	}
	
	@Test
	void separatedSignatureAndArchiveTimestampsTest() {

		Calendar calendar = Calendar.getInstance();

		List<TimestampWrapper> timestamps = new ArrayList<>();
		timestamps.add(getTimestampWrapper("T-1", calendar.getTime(), TimestampType.CONTENT_TIMESTAMP));
		calendar.add(Calendar.SECOND, 1);
		Date productionTime = calendar.getTime();
		timestamps.add(getTimestampWrapper("T-2-1", productionTime, TimestampType.SIGNATURE_TIMESTAMP, "T-1"));
		timestamps.add(getTimestampWrapper("T-2-2", productionTime, TimestampType.SIGNATURE_TIMESTAMP, "T-2"));
		calendar.add(Calendar.SECOND, 1);
		productionTime = calendar.getTime();
		timestamps.add(getTimestampWrapper("T-3-1", productionTime, TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2-1"));
		timestamps.add(getTimestampWrapper("T-3-2", productionTime, TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2-2"));
		
		validate(timestamps, XmlStatus.OK);
	}
	
	@Test
	void separatedSignatureAndArchiveTimestampsDifferentTimeTest() {

		Calendar calendar = Calendar.getInstance();

		List<TimestampWrapper> timestamps = new ArrayList<>();
		timestamps.add(getTimestampWrapper("T-a", calendar.getTime(), TimestampType.CONTENT_TIMESTAMP));
		timestamps.add(getTimestampWrapper("T-b", calendar.getTime(), TimestampType.CONTENT_TIMESTAMP));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-2-1", calendar.getTime(), TimestampType.SIGNATURE_TIMESTAMP, "T-a"));
		timestamps.add(getTimestampWrapper("T-2-2", calendar.getTime(), TimestampType.SIGNATURE_TIMESTAMP, "T-a", "T-b"));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-3-1", calendar.getTime(), TimestampType.ARCHIVE_TIMESTAMP, "T-a", "T-2-1"));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-3-2", calendar.getTime(), TimestampType.ARCHIVE_TIMESTAMP, "T-a", "T-b", "T-2-2"));
		
		validate(timestamps, XmlStatus.OK);
	}
	
	@Test
	void typeOrderFailCheckTest() {

		Calendar calendar = Calendar.getInstance();

		List<TimestampWrapper> timestamps = new ArrayList<>();
		timestamps.add(getTimestampWrapper("T-1", calendar.getTime(), TimestampType.SIGNATURE_TIMESTAMP));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-2", calendar.getTime(), TimestampType.CONTENT_TIMESTAMP));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-3", calendar.getTime(), TimestampType.VALIDATION_DATA_TIMESTAMP));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-4", calendar.getTime(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3"));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-5", calendar.getTime(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3", "T-4"));
		
		validate(timestamps, XmlStatus.NOT_OK);
	}
	
	@Test
	void timeOrderFailCheckTest() {

		Calendar beforeAll = Calendar.getInstance();

		Calendar calendar = Calendar.getInstance();

		List<TimestampWrapper> timestamps = new ArrayList<>();
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-1", calendar.getTime(), TimestampType.CONTENT_TIMESTAMP));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-2", calendar.getTime(), TimestampType.SIGNATURE_TIMESTAMP, "T-1"));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-3", calendar.getTime(), TimestampType.VALIDATION_DATA_TIMESTAMP));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-4", calendar.getTime(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3"));
		timestamps.add(getTimestampWrapper("T-5", beforeAll.getTime(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3", "T-4"));
		
		validate(timestamps, XmlStatus.NOT_OK);
	}
	
	@Test
	void refOrderFailCheckTest() {

		Calendar calendar = Calendar.getInstance();

		List<TimestampWrapper> timestamps = new ArrayList<>();
		timestamps.add(getTimestampWrapper("T-1", calendar.getTime(), TimestampType.CONTENT_TIMESTAMP));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-2", calendar.getTime(), TimestampType.SIGNATURE_TIMESTAMP, "T-1"));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-3", calendar.getTime(), TimestampType.VALIDATION_DATA_TIMESTAMP));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-4", calendar.getTime(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3", "T-5"));
		calendar.add(Calendar.SECOND, 1);
		timestamps.add(getTimestampWrapper("T-5", calendar.getTime(), TimestampType.ARCHIVE_TIMESTAMP, "T-1", "T-2", "T-3"));
		
		validate(timestamps, XmlStatus.NOT_OK);
	}
	
	private void validate(List<TimestampWrapper> timestamps, XmlStatus expectedResult) {
		TimestampCoherenceOrderCheck tcoc = new TimestampCoherenceOrderCheck(i18nProvider, result, timestamps,
				new LevelConstraintWrapper(constraint));
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
