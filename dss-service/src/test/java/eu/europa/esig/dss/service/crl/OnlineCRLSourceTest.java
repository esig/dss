package eu.europa.esig.dss.service.crl;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;

public class OnlineCRLSourceTest {

	private static final String alternative_url = "http://dss.nowina.lu/pki-factory/crl/root-ca.crl";
	private static final String wrong_url = "http://wrong.url";
	
	private static OnlineCRLSource onlineCRLSource;
	private static CommonsDataLoader dataLoader;
	
	private static CertificateToken goodUser;
	private static CertificateToken goodCa;
	private static CertificateToken rootCa;
	
	@BeforeAll
	public static void init() {		
		goodUser = DSSUtils.loadCertificate(new File("src/test/resources/good-user.crt"));
		goodCa = DSSUtils.loadCertificate(new File("src/test/resources/good-ca.crt"));
		rootCa = DSSUtils.loadCertificate(new File("src/test/resources/root-ca.crt"));
	}
	
	@BeforeEach
	public void initSource() {
		dataLoader = new CommonsDataLoader();
		onlineCRLSource = new OnlineCRLSource(dataLoader);
	}
	
	@Test
	public void getRevocationTokenTest() {
		CRLToken revocationToken = onlineCRLSource.getRevocationToken(goodUser, goodCa);
		assertNull(revocationToken);
		
		revocationToken = onlineCRLSource.getRevocationToken(goodCa, rootCa);
		assertNotNull(revocationToken);
	}
	
	@Test
	public void getRevocationTokenWithAlternateUrlTest() {
		assertThrows(DSSException.class, () -> {
			onlineCRLSource.getRevocationToken(goodUser, goodCa, Arrays.asList(alternative_url));
		});
		
		CRLToken revocationToken = onlineCRLSource.getRevocationToken(goodCa, rootCa, Arrays.asList(alternative_url));
		assertNotNull(revocationToken);
	}
	
	@Test
	public void getRevocationTokenWithWrongAlternateUrlTest() {
		CRLToken revocationToken = onlineCRLSource.getRevocationToken(goodUser, goodCa, Arrays.asList(wrong_url));
		assertNull(revocationToken);
		
		revocationToken = onlineCRLSource.getRevocationToken(goodCa, rootCa, Arrays.asList(wrong_url));
		assertNotNull(revocationToken);
	}
	
	@Test
	public void timeoutTest() {
		dataLoader.setTimeoutConnection(1);
		CRLToken revocationToken = onlineCRLSource.getRevocationToken(goodUser, goodCa, Arrays.asList(wrong_url, alternative_url));
		assertNull(revocationToken);
		
		revocationToken = onlineCRLSource.getRevocationToken(goodCa, rootCa, Arrays.asList(wrong_url, alternative_url));
		assertNull(revocationToken);
	}

}
