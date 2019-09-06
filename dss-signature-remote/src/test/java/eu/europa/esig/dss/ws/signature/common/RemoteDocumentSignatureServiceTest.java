package eu.europa.esig.dss.ws.signature.common;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

public class RemoteDocumentSignatureServiceTest extends AbstractRemoteSignatureServiceTest {
	
	private RemoteDocumentSignatureServiceImpl signatureService;
	
	@BeforeEach
	public void init() {
		signatureService = new RemoteDocumentSignatureServiceImpl();
		signatureService.setXadesService(getXAdESService());
	}

	@Test
	public void testSigningAndExtension() throws Exception {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		RemoteDocument toSignDocument = new RemoteDocument(Utils.toByteArray(fileToSign.openStream()), fileToSign.getName());
		ToBeSignedDTO dataToSign = signatureService.getDataToSign(toSignDocument, parameters);
		assertNotNull(dataToSign);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(toSignDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(signedDocument);

		parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);

		RemoteDocument extendedDocument = signatureService.extendDocument(signedDocument, parameters);

		assertNotNull(extendedDocument);

		InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
		validate(iMD, null);
	}

	@Test
	public void testSigningAndExtensionDigestDocument() throws Exception {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.digest(DigestAlgorithm.SHA256, fileToSign), DigestAlgorithm.SHA256,
				fileToSign.getName());

		ToBeSignedDTO dataToSign = signatureService.getDataToSign(toSignDocument, parameters);
		assertNotNull(dataToSign);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(toSignDocument, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(signedDocument);

		parameters = new RemoteSignatureParameters();
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
		parameters.setDetachedContents(Arrays.asList(toSignDocument));

		RemoteDocument extendedDocument = signatureService.extendDocument(signedDocument, parameters);

		assertNotNull(extendedDocument);

		InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
		validate(iMD, RemoteDocumentConverter.toDSSDocuments(Arrays.asList(toSignDocument)));
	}

}
