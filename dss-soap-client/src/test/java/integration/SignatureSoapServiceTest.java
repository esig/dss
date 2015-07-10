package integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import eu.europa.esig.dss.BLevelParameters;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.InMemoryDocument;
import eu.europa.esig.dss.RemoteCertificate;
import eu.europa.esig.dss.RemoteDocument;
import eu.europa.esig.dss.RemoteSignatureParameters;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.SignaturePackaging;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.signature.DataToSignDTO;
import eu.europa.esig.dss.signature.ExtendDocumentDTO;
import eu.europa.esig.dss.signature.SignDocumentDTO;
import eu.europa.esig.dss.signature.SoapDocumentSignatureService;
import eu.europa.esig.dss.test.TestUtils;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.test.mock.MockPrivateKeyEntry;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "/test-soap-context.xml")
public class SignatureSoapServiceTest {

	@Autowired
	private SoapDocumentSignatureService soapClient;

	@Test
	public void testSigningAndExtension() throws Exception {
		CertificateService certificateService = new CertificateService();

		MockPrivateKeyEntry entry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSigningCertificate(new RemoteCertificate(entry.getCertificate().getCertificate().getEncoded()));
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		RemoteDocument toSignDocument = new RemoteDocument(new FileDocument(new File("src/test/resources/sample.xml")));

		ToBeSigned dataToSign = soapClient.getDataToSign(new DataToSignDTO(toSignDocument, parameters));
		assertNotNull(dataToSign);

		SignatureValue signatureValue = TestUtils.sign(SignatureAlgorithm.RSA_SHA256, entry, dataToSign);
		SignDocumentDTO signDocument = new SignDocumentDTO(toSignDocument, parameters, signatureValue);
		RemoteDocument signedDocument = soapClient.signDocument(signDocument);

		assertNotNull(signedDocument);

		parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);
		parameters.setSigningCertificate(new RemoteCertificate(entry.getCertificate().getCertificate().getEncoded()));
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		RemoteDocument extendedDocument = soapClient.extendDocument(new ExtendDocumentDTO(signedDocument, parameters));

		assertNotNull(extendedDocument);

		InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
		iMD.save("target/test.xml");
	}

	@Test
	public void testBLevel() throws Exception {
		BLevelParameters level = new BLevelParameters();

		Thread.sleep(10000);

		BLevelParameters bLevel = soapClient.getBLevel(level);

		System.out.println(level);
		System.out.println(bLevel);
		assertEquals(bLevel, level);
	}

	@Test
	public void testParams() throws Exception {
		RemoteSignatureParameters params = new RemoteSignatureParameters();

		Thread.sleep(10000);

		RemoteSignatureParameters params2 = soapClient.getParams(params);

		System.out.println(params);
		System.out.println(params2);
		assertEquals(params, params2);

	}

}
