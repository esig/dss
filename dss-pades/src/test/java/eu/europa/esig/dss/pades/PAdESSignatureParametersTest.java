package eu.europa.esig.dss.pades;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;

public class PAdESSignatureParametersTest extends PKIFactoryAccess {
	
	private String signingAlias;
	
	@Test
	public void test() throws IOException {
		Date date = new Date();
		
		PAdESSignatureParameters padesSignatureParameters = new PAdESSignatureParameters();
		padesSignatureParameters.bLevel().setSigningDate(date);
		
		byte[] serialized = Utils.serialize(padesSignatureParameters);
		
		PAdESSignatureParameters padesSignatureParametersTwo = new PAdESSignatureParameters();
		padesSignatureParametersTwo.bLevel().setSigningDate(date);
		
		byte[] serializedTwo = Utils.serialize(padesSignatureParametersTwo);
		
		assertArrayEquals(serialized, serializedTwo);
		
		padesSignatureParameters.setSignerName("Nowina");
		serialized = Utils.serialize(padesSignatureParameters);
		assertFalse(Arrays.equals(serialized, serializedTwo));
		
		padesSignatureParametersTwo.setSignerName("NowinaSolutions");
		serializedTwo = Utils.serialize(padesSignatureParametersTwo);
		assertFalse(Arrays.equals(serialized, serializedTwo));
		
		padesSignatureParametersTwo.setSignerName("Nowina");
		serializedTwo = Utils.serialize(padesSignatureParametersTwo);
		assertArrayEquals(serialized, serializedTwo);
		
		signingAlias = GOOD_USER;
		padesSignatureParameters.setSigningCertificate(getSigningCert());
		serialized = Utils.serialize(padesSignatureParameters);
		assertFalse(Arrays.equals(serialized, serializedTwo));

		signingAlias = SELF_SIGNED_USER;
		padesSignatureParametersTwo.setSigningCertificate(getSigningCert());
		serializedTwo = Utils.serialize(padesSignatureParametersTwo);
		assertFalse(Arrays.equals(serialized, serializedTwo));

		signingAlias = GOOD_USER;
		padesSignatureParametersTwo.setSigningCertificate(getSigningCert());
		serializedTwo = Utils.serialize(padesSignatureParametersTwo);
		assertArrayEquals(serialized, serializedTwo);
		
		CertificateToken signingCertificate = padesSignatureParametersTwo.getSigningCertificate();
		signingCertificate.isSignedBy(signingCertificate);
		serializedTwo = Utils.serialize(padesSignatureParametersTwo);
		assertArrayEquals(serialized, serializedTwo);
		
		PAdESTimestampParameters archiveTimestampParameters = padesSignatureParametersTwo.getArchiveTimestampParameters();
		archiveTimestampParameters.setFilter("TSTFilter");
		serializedTwo = Utils.serialize(padesSignatureParametersTwo);
		assertFalse(Arrays.equals(serialized, serializedTwo));
	}

	@Override
	protected String getSigningAlias() {
		return signingAlias;
	}

}
