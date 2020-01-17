package eu.europa.esig.dss.cades.timestamp;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.test.signature.PKIFactoryAccess;

public class UnsupportedOperationTimestampCAdESTest extends PKIFactoryAccess {

	@Test
	public void unsupportedOperationException() throws IOException {
		CAdESService service = new CAdESService(getOfflineCertificateVerifier());
		service.setTspSource(getAlternateGoodTsa());

		DSSDocument documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);

		CAdESTimestampParameters timestampParameters = new CAdESTimestampParameters();
		assertThrows(UnsupportedOperationException.class, () -> service.timestamp(documentToSign, timestampParameters));
	}

	@Override
	protected String getSigningAlias() {
		return null;
	}

}
