package eu.europa.esig.dss.x509;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Set;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.tsl.KeyUsageBit;

public class CertificateTokenTest {

	private static final Logger logger = LoggerFactory.getLogger(CertificateTokenTest.class);

	@Test
	public void getKeyUsageBits() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
		Set<KeyUsageBit> keyUsageBits = certificate.getKeyUsageBits();
		logger.info("Key usage citizen_ca : " + keyUsageBits);
		assertTrue(keyUsageBits.contains(KeyUsageBit.crlSign));

		certificate = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
		keyUsageBits = certificate.getKeyUsageBits();
		logger.info("Key usage tsp cert : " + keyUsageBits);
		assertFalse(keyUsageBits.contains(KeyUsageBit.crlSign));
	}

}
