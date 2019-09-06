package eu.europa.esig.dss.xades.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XPathQueryHolder;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class ExtendWithLastTimestampValidationDataTest extends PKIFactoryAccess {

	@Test
	public void test() throws Exception {
		/* Test that new TimeStampValidation data added instead of the old element */
		
		DSSDocument documentToSign = new FileDocument("src/test/resources/sample.xml");
		
		XAdESSignatureParameters parameters = new XAdESSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		parameters.setSigningCertificate(getSigningCert());
		parameters.setCertificateChain(getCertificateChain());
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        XAdESService service = new XAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getAlternateGoodTsa());

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, parameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
        DSSDocument signedDocument = service.signDocument(documentToSign, parameters, signatureValue);
        
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        service.setTspSource(getGoodTsa());
        
		DSSDocument extendedDocument = service.extendDocument(signedDocument, parameters);
		
		DSSDocument doubleExtendedDocument = service.extendDocument(extendedDocument, parameters);
		
		Document extendedDocDom = DomUtils.buildDOM(doubleExtendedDocument);
		XPathQueryHolder xPathQueryHolder = new XPathQueryHolder();
		NodeList signatures = DomUtils.getNodeList(extendedDocDom, "//" + XPathQueryHolder.ELEMENT_SIGNATURE);
		assertEquals(1, signatures.getLength());
		Node signatureElement = signatures.item(0);
		Node unsignedSignatureProperties = DomUtils.getNode(signatureElement, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
		Node lastArchveTST = unsignedSignatureProperties.getLastChild();
		unsignedSignatureProperties.removeChild(lastArchveTST);
		
		NodeList timestampValidationData = DomUtils.getNodeList(extendedDocDom, "//xades141:TimeStampValidationData");
		assertEquals(1, timestampValidationData.getLength());
		
		DSSDocument ltaWithTSValidationData = DomUtils.createDssDocumentFromDomDocument(extendedDocDom, "LTAWithTimeStampValidationData.xml");
		// ltaWithTSValidationData.save("target/" + ltaWithTSValidationData.getName());

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(ltaWithTSValidationData);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		Reports reports = validator.validateDocument();
		
		DiagnosticData diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		
		List<TimestampWrapper> timestamps = diagnosticData.getTimestampList();
		assertEquals(2, timestamps.size());
		
		Set<RevocationWrapper> allRevocationData = diagnosticData.getAllRevocationData();
		assertEquals(2, allRevocationData.size());

		DSSDocument newExtendedDocument = service.extendDocument(ltaWithTSValidationData, parameters);
		// newExtendedDocument.save("target/result.xml");

		validator = SignedDocumentValidator.fromDocument(newExtendedDocument);
		validator.setCertificateVerifier(getOfflineCertificateVerifier());
		reports = validator.validateDocument();
		
		diagnosticData = reports.getDiagnosticData();
		assertNotNull(diagnosticData);
		
		timestamps = diagnosticData.getTimestampList();
		assertEquals(3, timestamps.size());
		
		int archiveTimestampCounter = 0;
		for (TimestampWrapper timestamp : timestamps) {
			if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestamp.getType())) {
				archiveTimestampCounter++;
			}
			assertTrue(timestamp.isMessageImprintDataFound());
			assertTrue(timestamp.isMessageImprintDataIntact());
		}
		assertEquals(2, archiveTimestampCounter);
		
		allRevocationData = diagnosticData.getAllRevocationData();
		assertEquals(2, allRevocationData.size());

		Document newExtendedDocDom = DomUtils.buildDOM(newExtendedDocument);
		timestampValidationData = DomUtils.getNodeList(newExtendedDocDom, "//xades141:TimeStampValidationData");
		assertEquals(1, timestampValidationData.getLength());
		
	}

	@Override
	protected String getSigningAlias() {
		return RSA_SHA3_USER;
	}

}