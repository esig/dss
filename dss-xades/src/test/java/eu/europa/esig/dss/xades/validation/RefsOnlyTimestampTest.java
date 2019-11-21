package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.HashSet;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DefaultDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;

public class RefsOnlyTimestampTest {
	
	@Test
	public void test() {
		// the timestamp is broken in the file
		DSSDocument doc = new FileDocument("src/test/resources/validation/signing-cert-multiple-refs-sig.xml");
		DefaultDocumentValidator validator = DefaultDocumentValidator.fromDocument(doc);
		CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
		validator.setCertificateVerifier(commonCertificateVerifier);
		
		Reports reports = validator.validateDocument();
		assertNotNull(reports);
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		
		int signatureTimestampCounter = 0;
		int refsOnlyTimestampCounter = 0;
		boolean coversSignature = false;
		boolean coversTimestamp = false;
		for (TimestampWrapper timestampWrapper : timestampList) {
			if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
				signatureTimestampCounter++;
			} else if (TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP.equals(timestampWrapper.getType())) {
				List<XmlTimestampedObject> timestampedObjects = timestampWrapper.getTimestampedObjects();
				assertEquals(6, timestampedObjects.size());
				assertDoesNotContainDuplicates(timestampedObjects);
				
				for (XmlTimestampedObject timestampedReference : timestampedObjects) {
					if (diagnosticData.getSignatureIdList().contains(timestampedReference.getToken().getId())) {
						coversSignature = true;
					}
					if (diagnosticData.getTimestampIdList(diagnosticData.getFirstSignatureId()).contains(timestampedReference.getToken().getId())) {
						coversTimestamp = true;
					}
				}
				
				refsOnlyTimestampCounter++;
			}
		}
		
		assertEquals(1, signatureTimestampCounter);
		assertEquals(1, refsOnlyTimestampCounter);
		assertFalse(coversSignature);
		assertFalse(coversTimestamp);
		
	}
	
	private void assertDoesNotContainDuplicates(List<XmlTimestampedObject> timestampedObjects) {
		HashSet<XmlTimestampedObject> timestampedObjectsSet = new HashSet<XmlTimestampedObject>(timestampedObjects);
		assertEquals(timestampedObjectsSet.size(), timestampedObjects.size());
	}

}
