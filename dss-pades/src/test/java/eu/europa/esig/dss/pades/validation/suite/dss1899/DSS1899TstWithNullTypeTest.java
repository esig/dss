package eu.europa.esig.dss.pades.validation.suite.dss1899;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.utils.Utils;

public class DSS1899TstWithNullTypeTest extends AbstractPAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-tst-with-null-type.pdf"));
	}
	
	@Override
	protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
		super.checkNumberOfSignatures(diagnosticData);
		
		assertEquals(1, diagnosticData.getSignatures().size());
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		super.checkSignatureLevel(diagnosticData);
		
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertEquals(SignatureLevel.PAdES_BASELINE_LTA, signature.getSignatureFormat());
	}
	
	@Override
	protected void checkPdfRevision(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		
		assertNotNull(signature.getFirstFieldName());
		assertTrue(Utils.isCollectionNotEmpty(signature.getSignatureFieldNames()));
		assertEquals(1, signature.getSignatureFieldNames().size());
		assertNotNull(signature.getSignatureDictionaryType());
		assertNotNull(signature.getFilter());
		assertNotNull(signature.getSubFilter());
		assertNotNull(signature.getSignatureByteRange());
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(2, timestampList.size());
		TimestampWrapper archiveTimestamp = null;
		for (TimestampWrapper timestamp : timestampList) {
			if (timestamp.getType().isArchivalTimestamp()) {
				archiveTimestamp = timestamp;
			}
		}
		
		assertNotNull(archiveTimestamp);
		assertNull(archiveTimestamp.getSignatureDictionaryType());
		assertTrue(Utils.isCollectionNotEmpty(archiveTimestamp.getSignatureFieldNames()));
		assertTrue(Utils.isCollectionNotEmpty(archiveTimestamp.getSignatureByteRange()));
		assertNotNull(archiveTimestamp.getFilter());
		assertNotNull(archiveTimestamp.getSubFilter());
	}

}
