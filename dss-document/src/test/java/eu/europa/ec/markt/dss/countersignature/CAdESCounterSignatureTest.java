package eu.europa.ec.markt.dss.countersignature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Collection;
import java.util.List;

import org.apache.pdfbox.io.IOUtils;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.junit.Test;

import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.mock.MockPrivateKeyEntry;
import eu.europa.ec.markt.dss.mock.MockSignatureTokenConnection;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.service.CertificateService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.FileDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.cades.CAdESService;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.CommonCertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.report.Reports;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

public class CAdESCounterSignatureTest {

	@Test
	public void test() throws Exception {
		CertificateService certificateService = new CertificateService();
		DSSPrivateKeyEntry entryUserA = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA1);
		MockPrivateKeyEntry entryUserB = (MockPrivateKeyEntry) certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		DSSDocument document = new FileDocument(new File("src/test/resources/sample.xml"));

		// Sign
		SignatureParameters signatureParameters = new SignatureParameters();
		signatureParameters.setSigningCertificate(entryUserA.getCertificate());
		signatureParameters.setCertificateChain(entryUserA.getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);

		CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
		CAdESService service = new CAdESService(certificateVerifier);

		byte[] dataToSign = service.getDataToSign(document, signatureParameters);
		byte[] signatureValue = sign(signatureParameters.getSignatureAlgorithm(), entryUserA.getPrivateKey(), dataToSign);
		DSSDocument signedDocument = service.signDocument(document, signatureParameters, signatureValue);

		// Countersign

		final InputStream inputStream = signedDocument.openStream();
		final CMSSignedData cmsSignedData = new CMSSignedData(inputStream);
		IOUtils.closeQuietly(inputStream);

		SignerInformationStore signerInfosStore = cmsSignedData.getSignerInfos();

		@SuppressWarnings("unchecked")
		Collection<SignerInformation> signerInfos = signerInfosStore.getSigners();
		assertEquals(1, signerInfos.size());
		SignerInformation signerInfo = signerInfos.iterator().next();

		SignatureParameters countersigningParameters = new SignatureParameters();
		countersigningParameters.setPrivateKeyEntry(entryUserB);
		countersigningParameters.setSigningToken(new MockSignatureTokenConnection());
		countersigningParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
		countersigningParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);

		DSSDocument counterSignDocument = service.counterSignDocument(signedDocument, countersigningParameters, signerInfo.getSID());
		assertNotNull(counterSignDocument);

		// Validate
		SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(counterSignDocument);
		validator.setCertificateVerifier(new CommonCertificateVerifier());
		Reports reports = validator.validateDocument();

		reports.print();

		DiagnosticData diagnosticData = reports.getDiagnosticData();

		List<XmlDom> signatures = diagnosticData.getElements("/DiagnosticData/Signature");
		assertEquals(2, signatures.size());

		boolean foundCounterSignature = false;
		for (XmlDom xmlDom : signatures) {
			String type = xmlDom.getAttribute("Type");
			if (AttributeValue.COUNTERSIGNATURE.equals(type)) {
				foundCounterSignature = true;
			}
			assertTrue(diagnosticData.isBLevelTechnicallyValid(xmlDom.getAttribute("Id")));
		}
		assertTrue(foundCounterSignature);
	}

	private byte[] sign(SignatureAlgorithm algo, PrivateKey privateKey, byte[] bytesToSign) throws GeneralSecurityException {
		final Signature signature = Signature.getInstance(algo.getJCEId());
		signature.initSign(privateKey);
		signature.update(bytesToSign);
		final byte[] signatureValue = signature.sign();
		return signatureValue;
	}

}
