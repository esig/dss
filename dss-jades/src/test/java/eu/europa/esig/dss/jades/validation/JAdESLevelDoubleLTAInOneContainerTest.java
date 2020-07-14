package eu.europa.esig.dss.jades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Collectors;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

public class JAdESLevelDoubleLTAInOneContainerTest extends AbstractJAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/double-lta-in-container.json");
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(3, timestampList.size());
		String signatureTstId = timestampList.get(0).getId();
		
		int archiveTstCounter = 0;
		List<String> timestampedObjectIds = null;
		for (TimestampWrapper timestamp : timestampList) {
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
			
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				assertEquals(ArchiveTimestampType.JAdES_ALL, timestamp.getArchiveTimestampType());
				assertTrue(Utils.isCollectionNotEmpty(timestamp.getTimestampedObjects()));
				++archiveTstCounter;
				List<String> currentTimestampedObjectIds = timestamp.getTimestampedObjects().stream().map(o -> o.getToken().getId()).collect(Collectors.toList());
				if (timestampedObjectIds == null) {
					timestampedObjectIds = currentTimestampedObjectIds;
				} else {
					assertEquals(timestampedObjectIds, currentTimestampedObjectIds);
				}
				assertTrue(currentTimestampedObjectIds.contains(signatureTstId));
			}
		}
		assertEquals(2, archiveTstCounter);
		assertNotEquals(timestampList.get(0).getSigningCertificate().getId(), timestampList.get(1).getSigningCertificate().getId());
		
	}

}
