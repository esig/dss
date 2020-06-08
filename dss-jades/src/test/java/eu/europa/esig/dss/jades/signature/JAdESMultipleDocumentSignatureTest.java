package eu.europa.esig.dss.jades.signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;

public class JAdESMultipleDocumentSignatureTest extends AbstractMultipleDocumentSignatureTest {

	private JAdESSignatureParameters signatureParameters;
	private List<DSSDocument> documentToSigns;

	@BeforeEach
	public void init() throws Exception {
		documentToSigns = Arrays.<DSSDocument> asList(new FileDocument("src/test/resources/sample.json"),
				new FileDocument("src/test/resources/sample.png"),
				new InMemoryDocument("Hello World!".getBytes(), "helloWorld"));

		signatureParameters = new JAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
	}
	
	@Test
	public void test() {
		Exception exception = assertThrows(DSSException.class, () -> getService().getDataToSign(documentToSigns, signatureParameters));
		assertEquals("Not supported operation (only DETACHED are allowed for multiple document signing)!", exception.getMessage());
	}
	
	@Override
	public void signAndVerify() {
		// do nothing
	}

	@Override
	protected MultipleDocumentsSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
		return new JAdESService(getOfflineCertificateVerifier());
	}

	@Override
	protected JAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected List<DSSDocument> getDocumentsToSign() {
		return documentToSigns;
	}

}
