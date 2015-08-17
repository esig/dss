package eu.europa.esig.dss.tsl.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.junit.Test;

import eu.europa.esig.dss.tsl.TSLPointer;
import eu.europa.esig.dss.tsl.TSLValidationModel;

public class TSLParserTest {

	@Test
	public void parse() {
		TSLParser parser = new TSLParser();
		TSLValidationModel model = parser.parseTSL(new File("src/test/resources/LOTL.xml"));
		assertNotNull(model);
		assertNotNull(model.getNextUpdateDate());
		assertNotNull(model.getIssueDate());
		assertEquals("EU", model.getTerritory());
		assertEquals(115, model.getSequenceNumber());
		List<TSLPointer> pointers = model.getPointers();
		assertTrue(CollectionUtils.isNotEmpty(pointers));
		for (TSLPointer tslPointer : pointers) {
			assertTrue(StringUtils.isNotEmpty(tslPointer.getMimeType()));
			assertTrue(StringUtils.isNotEmpty(tslPointer.getTerritory()));
			assertTrue(StringUtils.isNotEmpty(tslPointer.getXmlUrl()));
			assertTrue(CollectionUtils.isNotEmpty(tslPointer.getPotentialSigners()));
		}
		assertTrue(CollectionUtils.isNotEmpty(model.getDistributionPoints()));
	}

}
