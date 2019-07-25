package eu.europa.esig.dss.xades.signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.signature.PKIFactoryAccess;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.XPath2FilterEnvelopedSignatureTransform;

public class XAdESXPath2FilterDoubleSignatureTest extends PKIFactoryAccess {

	@Test
	public void test() throws IOException {

		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.xml"));

		XAdESService service = new XAdESService(getCompleteCertificateVerifier());

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		setXPath2Transformation(toBeSigned, params, "REF1");

		ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
		SignatureValue signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

		params = new XAdESSignatureParameters();
		params.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		params.setSignaturePackaging(SignaturePackaging.ENVELOPED);
		params.setSigningCertificate(getSigningCert());
		setXPath2Transformation(signedDocument, params, "REF2");

		dataToSign = service.getDataToSign(signedDocument, params);
		signatureValue = getToken().sign(dataToSign, params.getDigestAlgorithm(), getPrivateKeyEntry());
		DSSDocument doubleSignedDocument = service.signDocument(signedDocument, params, signatureValue);
		doubleSignedDocument.save("target/" + "doubleSignedTest.xml");

		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
		validator.setCertificateVerifier(getCompleteCertificateVerifier());

		Reports reports = validator.validateDocument();
		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<String> signatureIdList = diagnosticData.getSignatureIdList();
		assertEquals(2, signatureIdList.size());
		for (String signatureId : signatureIdList) {
			assertTrue(diagnosticData.isBLevelTechnicallyValid(signatureId));
		}

		assertFalse(DSSXMLUtils.isDuplicateIdsDetected(doubleSignedDocument));
	}
	
	private void setXPath2Transformation(DSSDocument documentToSign, XAdESSignatureParameters signatureParameters, String id) {

		List<DSSReference> dssReferences = new ArrayList<DSSReference>();
		DSSReference reference = new DSSReference();
		reference.setContents(documentToSign);
		reference.setId(id);
		reference.setDigestMethodAlgorithm(DigestAlgorithm.SHA256);
		reference.setUri("");
		List<DSSTransform> transforms1 = new ArrayList<DSSTransform>();
		XPath2FilterEnvelopedSignatureTransform transform1 = new XPath2FilterEnvelopedSignatureTransform();
		transforms1.add(transform1);
		reference.setTransforms(transforms1);
		dssReferences.add(reference);

		signatureParameters.setReferences(dssReferences);
		
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
