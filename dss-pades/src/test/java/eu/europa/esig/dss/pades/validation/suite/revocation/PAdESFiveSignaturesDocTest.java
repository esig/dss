package eu.europa.esig.dss.pades.validation.suite.revocation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.OrphanTokenWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.SignerDataWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.validation.suite.AbstractPAdESTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.validationreport.jaxb.SignersDocumentType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;

public class PAdESFiveSignaturesDocTest extends AbstractPAdESTestValidation {
	
	private static byte[] previousSignatureSignerDocumentDigest = null;

	@Override
	protected DSSDocument getSignedDocument() {
		return new InMemoryDocument(getClass().getResourceAsStream("/validation/pades-5-signatures-and-1-document-timestamp.pdf"));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		super.checkTimestamps(diagnosticData);
		
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
		assertNotNull(timestamps);
		assertEquals(3, timestamps.size());
		List<String> usedTimestampIds = new ArrayList<>();
		for (TimestampWrapper timestamp : timestamps) {
			assertFalse(usedTimestampIds.contains(timestamp.getId()));
			usedTimestampIds.add(timestamp.getId());
			List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
			List<String> usedTimestampObjectIds = new ArrayList<>();
			for (XmlTimestampedObject timestampedObject : timestampedObjects) {
				assertFalse(usedTimestampObjectIds.contains(timestampedObject.getToken().getId()));
				usedTimestampObjectIds.add(timestampedObject.getToken().getId());
			}
		}
		
		SignatureWrapper secondSignature = diagnosticData.getSignatures().get(1);

		List<TimestampWrapper> secondSignatureTimestamps = secondSignature.getTimestampList();
		assertEquals(2, secondSignatureTimestamps.size());
		TimestampWrapper signatureTimestamp = secondSignatureTimestamps.get(0);
		assertEquals(4, signatureTimestamp.getTimestampedObjects().size());
		assertEquals(TimestampType.SIGNATURE_TIMESTAMP, signatureTimestamp.getType());
        
        TimestampWrapper archiveTimestamp = null;
        int archiveTimestamps = 0;
        for (TimestampWrapper timestamp : timestamps) {
        	if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
        		archiveTimestamp = timestamp;
        		++archiveTimestamps;
        	}
        }
        assertNotNull(archiveTimestamp);
        assertEquals(1, archiveTimestamps);

        List<String> checkedIds = new ArrayList<>();
        
        assertEquals(5, archiveTimestamp.getTimestampedSignatures().size());
        checkedIds.add(archiveTimestamp.getTimestampedSignatures().get(0).getId());
        
        List<SignerDataWrapper> timestampedSignedData = archiveTimestamp.getTimestampedSignedData();
        assertEquals(5, timestampedSignedData.size());
        for (SignerDataWrapper signerDataWrapper : timestampedSignedData) {
            assertFalse(checkedIds.contains(signerDataWrapper.getId()));
            checkedIds.add(signerDataWrapper.getId());
        }
        
        List<CertificateWrapper> timestampedCertificates = archiveTimestamp.getTimestampedCertificates();
        assertEquals(18, timestampedCertificates.size());
        for (CertificateWrapper certificateWrapper : timestampedCertificates) {
            assertFalse(checkedIds.contains(certificateWrapper.getId()));
            checkedIds.add(certificateWrapper.getId());
        }
        
        List<RevocationWrapper> timestampedRevocations = archiveTimestamp.getTimestampedRevocations();
        assertEquals(2, timestampedRevocations.size());
        for (RevocationWrapper revocationWrapper : timestampedRevocations) {
            assertFalse(checkedIds.contains(revocationWrapper.getId()));
            checkedIds.add(revocationWrapper.getId());
        }
        
        List<OrphanTokenWrapper> timestampedOrphanRevocations = archiveTimestamp.getTimestampedOrphanRevocations();
        assertEquals(2, timestampedOrphanRevocations.size());
        for (OrphanTokenWrapper revocationWrapper : timestampedOrphanRevocations) {
            assertFalse(checkedIds.contains(revocationWrapper.getId()));
            checkedIds.add(revocationWrapper.getId());
        }
        
        List<TimestampWrapper> timestampedTimestamps = archiveTimestamp.getTimestampedTimestamps();
        assertEquals(2, timestampedTimestamps.size());
        for (TimestampWrapper timestampWrapper : timestampedTimestamps) {
            assertFalse(checkedIds.contains(timestampWrapper.getId()));
            checkedIds.add(timestampWrapper.getId());
        }
        
        assertEquals(30, checkedIds.size());
	}
	
	@Override
	protected void checkOrphanTokens(DiagnosticData diagnosticData) {
		assertEquals(0, diagnosticData.getAllOrphanCertificateObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanCertificateReferences().size());
		assertEquals(2, diagnosticData.getAllOrphanRevocationObjects().size());
		assertEquals(0, diagnosticData.getAllOrphanRevocationReferences().size());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertFalse(signatureWrapper.isBLevelTechnicallyValid());
		}
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertTrue(signatureWrapper.isDigestValuePresent());
			assertTrue(signatureWrapper.isDigestValueMatch());
			assertTrue(signatureWrapper.isIssuerSerialMatch());
		}
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
			assertTrue(!signatureWrapper.isThereTLevel() || signatureWrapper.isTLevelTechnicallyValid());
			assertTrue(!signatureWrapper.isThereALevel() || signatureWrapper.isALevelTechnicallyValid());
		}
	}
	
	@Override
	protected void validateETSISignerDocuments(List<SignersDocumentType> signersDocuments) {
		super.validateETSISignerDocuments(signersDocuments);
		
		SignersDocumentType signersDocument = signersDocuments.get(0);
		assertNotNull(signersDocument);
		DigestAlgAndValueType digestAlgAndValue = signersDocument.getDigestAlgAndValue();
		assertNotNull(digestAlgAndValue);
		byte[] digestValue = digestAlgAndValue.getDigestValue();
		assertTrue(Utils.isArrayNotEmpty(digestValue));
		assertFalse(Arrays.equals(digestValue, previousSignatureSignerDocumentDigest));
		previousSignatureSignerDocumentDigest = digestValue;
	}

}
