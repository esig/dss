package eu.europa.esig.dss.jades.signature;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.test.signature.AbstractPkiFactoryTestDocumentSignatureService;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public abstract class AbstractJAdESTestSignature extends AbstractPkiFactoryTestDocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> {

	@Override
	protected List<DSSDocument> getOriginalDocuments() {
		return Collections.singletonList(getDocumentToSign());
	}

	@Override
	protected MimeType getExpectedMime() {
		return MimeType.JOSE;
	}

	@Override
	protected boolean isBaselineT() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	protected boolean isBaselineLTA() {
		// TODO Auto-generated method stub
		return false;
	}

	// TODO : temporary fix!!! not implemented yet
	@Override
	protected void checkBLevelValid(DiagnosticData diagnosticData) {
		SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertTrue(signatureWrapper.isSignatureIntact());
	}

	// TODO : temporary fix!!! not implemented yet
	@Override
	protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
		// do nothing
	}

	// TODO : temporary fix!!! not implemented yet
	@Override
	protected void validateEtsiSignatureIdentifier(SignatureIdentifierType signatureIdentifier) {
		assertNotNull(signatureIdentifier);
		assertNotNull(signatureIdentifier.getId());
		assertNotNull(signatureIdentifier.getSignatureValue());
	}

	// TODO : temporary fix!!! not implemented yet
	@Override
	protected void getOriginalDocument(DSSDocument signedDocument, DiagnosticData diagnosticData) throws IOException {
		// do nothing
	}

	// TODO : temporary fix!!! not implemented yet
	@Override
	protected void verifyETSIValidationReport(ValidationReportType etsiValidationReportJaxb) {
		// do nothing
	}

}
