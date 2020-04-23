package eu.europa.esig.dss.xades.validation.dss1334;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.xades.validation.AbstractXAdESTestValidation;

public class DSS1334CryptoValidation extends AbstractXAdESTestValidation {

	private static final DSSDocument ORIGINAL_FILE = new FileDocument("src/test/resources/validation/dss1334/simple-test.xml");

	@Override
	protected DSSDocument getSignedDocument() {
		return new FileDocument("src/test/resources/validation/dss1334/simple-test.signed-only-detached-LuxTrustCA3.xml");
	}
	
	@Override
	protected List<DSSDocument> getDetachedContents() {
		return Collections.singletonList(ORIGINAL_FILE);
	}
	
	@Override
	protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signature.isSigningCertificateIdentified());
		assertTrue(signature.isSigningCertificateReferencePresent());
		assertFalse(signature.isSigningCertificateReferenceUnique());
		
		CertificateRefWrapper signingCertificateReference = signature.getSigningCertificateReference();
		assertNotNull(signingCertificateReference);
		assertTrue(signingCertificateReference.isDigestValuePresent());
		assertTrue(signingCertificateReference.isDigestValueMatch());
		assertTrue(signingCertificateReference.isIssuerSerialPresent());
		assertTrue(signingCertificateReference.isIssuerSerialMatch());
	}

}
