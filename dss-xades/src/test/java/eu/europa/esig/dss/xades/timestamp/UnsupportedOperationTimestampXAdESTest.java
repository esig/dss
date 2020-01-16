package eu.europa.esig.dss.xades.timestamp;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

public class UnsupportedOperationTimestampXAdESTest extends PKIFactoryAccess {

	@Test
	public void unsupportedOperationException() throws IOException {
		XAdESService service = new XAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());

		DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);
		DSSDocument documentToSign2 = new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT);
		List<DSSDocument> docs = Arrays.asList(documentToSign, documentToSign2);

		XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
		assertThrows(UnsupportedOperationException.class, () -> service.timestamp(documentToSign, signatureParameters));
		assertThrows(UnsupportedOperationException.class, () -> service.timestamp(docs, signatureParameters));
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
