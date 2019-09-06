package eu.europa.esig.dss.ws.signature.common;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;

public class RemoteMiltipleDocumentSignatureServiceTest extends AbstractRemoteSignatureServiceTest {
	
	private RemoteMultipleDocumentsSignatureServiceImpl signatureService;
	
	@BeforeEach
	public void init() {
		signatureService = new RemoteMultipleDocumentsSignatureServiceImpl();
		signatureService.setXadesService(getXAdESService());
		signatureService.setAsicWithXAdESService(getASiCXAdESService());
	}

	@Test
	public void testSigningAndExtensionMultiDocuments() throws Exception {
		RemoteSignatureParameters parameters = new RemoteSignatureParameters();
		parameters.setAsicContainerType(ASiCContainerType.ASiC_E);
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
		parameters.setSigningCertificate(RemoteCertificateConverter.toRemoteCertificate(getSigningCert()));
		parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

		FileDocument fileToSign = new FileDocument(new File("src/test/resources/sample.xml"));
		RemoteDocument toSignDocument = new RemoteDocument(DSSUtils.toByteArray(fileToSign), fileToSign.getName());
		RemoteDocument toSignDoc2 = new RemoteDocument("Hello world!".getBytes("UTF-8"), "test.bin");
		List<RemoteDocument> toSignDocuments = new ArrayList<RemoteDocument>();
		toSignDocuments.add(toSignDocument);
		toSignDocuments.add(toSignDoc2);
		ToBeSignedDTO dataToSign = signatureService.getDataToSign(toSignDocuments, parameters);
		assertNotNull(dataToSign);

		SignatureValue signatureValue = getToken().sign(DTOConverter.toToBeSigned(dataToSign), DigestAlgorithm.SHA256, getPrivateKeyEntry());
		RemoteDocument signedDocument = signatureService.signDocument(toSignDocuments, parameters,
				new SignatureValueDTO(signatureValue.getAlgorithm(), signatureValue.getValue()));

		assertNotNull(signedDocument);

		parameters = new RemoteSignatureParameters();
		parameters.setAsicContainerType(ASiCContainerType.ASiC_E);
		parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

		RemoteDocument extendedDocument = signatureService.extendDocument(signedDocument, parameters);

		assertNotNull(extendedDocument);

		InMemoryDocument iMD = new InMemoryDocument(extendedDocument.getBytes());
		// iMD.save("target/test.asice");
		
		validate(iMD, null);
	}

}
