package eu.europa.esig.dss.cades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.validationreport.jaxb.SignatureValidationReportType;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;
import eu.europa.esig.xades.jaxb.xades132.DigestAlgAndValueType;

public class CAdESLevelBWrongDetachedContext extends PKIFactoryAccess {
	
	@Test
	public void test() {
		DSSDocument documentToSign = new InMemoryDocument("Hello World".getBytes());
		
		CAdESSignatureParameters signatureParameters = new CAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(new Date());
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA1);

		CAdESService service = new CAdESService(getCompleteCertificateVerifier());

		ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
		SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);
		
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());
		validator.setDetachedContents(Arrays.asList(new InMemoryDocument("Bye World".getBytes())));
		
		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
		assertNotNull(signature);
		
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		assertEquals(1, digestMatchers.size());
		XmlDigestMatcher digestMatcher = digestMatchers.get(0);
		assertNotNull(digestMatcher.getDigestMethod());
		assertEquals(DigestAlgorithm.SHA1, digestMatcher.getDigestMethod());
		assertNotNull(digestMatcher.getDigestValue());
		assertTrue(digestMatcher.isDataFound());
		assertFalse(digestMatcher.isDataIntact());
		
		ValidationReportType etsiValidationReport = reports.getEtsiValidationReportJaxb();
		SignatureValidationReportType signatureValidationReport = etsiValidationReport.getSignatureValidationReport().get(0);
		assertNotNull(signatureValidationReport);
		SignatureIdentifierType signatureIdentifier = signatureValidationReport.getSignatureIdentifier();
		DigestAlgAndValueType digestAlgAndValue = signatureIdentifier.getDigestAlgAndValue();
		assertNotNull(digestAlgAndValue);
		assertNotNull(digestAlgAndValue.getDigestMethod());
		assertEquals(DigestAlgorithm.SHA1, DigestAlgorithm.forXML(digestAlgAndValue.getDigestMethod().getAlgorithm()));
		assertNotNull(digestAlgAndValue.getDigestValue());
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
