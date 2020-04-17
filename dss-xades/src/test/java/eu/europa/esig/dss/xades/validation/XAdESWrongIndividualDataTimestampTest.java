package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

public class XAdESWrongIndividualDataTimestampTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/Signature-X-CZ_ICZ-1.xml");
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(1, timestampList.size());
		
		TimestampWrapper timestampWrapper = timestampList.get(0);
		assertEquals(TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP, timestampWrapper.getType());
		
		assertFalse(timestampWrapper.isMessageImprintDataIntact());
		
		assertTrue(Utils.isCollectionEmpty(timestampWrapper.getTimestampedObjects()));
	}

}
