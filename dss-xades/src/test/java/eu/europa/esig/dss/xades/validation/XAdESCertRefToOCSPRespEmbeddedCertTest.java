package eu.europa.esig.dss.xades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.OrphanCertificateWrapper;
import eu.europa.esig.dss.diagnostic.OrphanRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.AdvancedSignature;

public class XAdESCertRefToOCSPRespEmbeddedCertTest extends AbstractXAdESTestValidation {

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument(new File("src/test/resources/validation/Signature-X-RO_TRA-4.xml"));
	}
	
	@Override
	protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
			DiagnosticData diagnosticData) {
		List<SignatureWrapper> signatures = diagnosticData.getSignatures();
		assertEquals(2, signatures.size());
		boolean signatureFound = false;
		for (SignatureWrapper signature : signatures) {
			if ("Signature-2064753652".equals(signature.getDAIdentifier())) {
				int completeCertificateRefsCounter = 0;
				for (RelatedCertificateWrapper foundCertificate : signature.foundCertificates().getRelatedCertificates()) {
					List<CertificateRefWrapper> certificateRefs = foundCertificate.getReferences();
					assertEquals(1, certificateRefs.size());
					CertificateRefWrapper xmlCertificateRef = certificateRefs.get(0);
					if (CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS.equals(xmlCertificateRef.getOrigin())) {
						completeCertificateRefsCounter++;
					}
					assertNotNull(foundCertificate.getId());
				}
				assertEquals(3, completeCertificateRefsCounter);
				signatureFound = true;
			}
		}
		assertTrue(signatureFound);
		
		List<OrphanCertificateWrapper> allOrphanCertificates = diagnosticData.getAllOrphanCertificateObjects();
		assertEquals(0, allOrphanCertificates.size());
		List<OrphanRevocationWrapper> allOrphanRevocations = diagnosticData.getAllOrphanRevocationObjects();
		assertEquals(0, allOrphanRevocations.size());
	}
	
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkSignatureLevel(DiagnosticData diagnosticData) {
		assertFalse(diagnosticData.isTLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
		assertFalse(diagnosticData.isALevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
	}
	
	@Override
	protected void checkTimestamps(DiagnosticData diagnosticData) {
		List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
		assertEquals(4, timestampList.size());
		int archiveTimestampCounter = 0;
		for (TimestampWrapper timestamp : timestampList) {
			List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
			for (XmlTimestampedObject timestampedObject : timestampedObjects) {
				assertNotNull(timestampedObject.getToken());
			}
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				archiveTimestampCounter++;
				assertEquals(ArchiveTimestampType.XAdES, timestamp.getArchiveTimestampType());
			}
		}
		assertEquals(1, archiveTimestampCounter);
	}

}
