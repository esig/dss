package eu.europa.esig.dss.x509;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.DSSUtils;

public class CommonCertificateSourceTest {

	private static final CertificateToken CERT = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));

	@Test
	public void emptyCommonCertificateSource() {
		CommonCertificateSource empty = new CommonCertificateSource();
		assertNotNull(empty.getCertificates());
		assertNotNull(empty.getCertificateSourceType());
		assertEquals(0, empty.getNumberOfCertificates());

		assertNotNull(empty.get(CERT.getSubjectX500Principal()));
	}

	@Test
	public void commonCertificateSource() {
		CertificatePool certPool = new CertificatePool();
		CommonCertificateSource ccc = new CommonCertificateSource(certPool);

		CertificateToken adddedCert = ccc.addCertificate(CERT);
		assertEquals(CERT, adddedCert);

		assertNotNull(ccc.getCertificates());
		assertNotNull(ccc.getCertificateSourceType());
		assertEquals(1, ccc.getNumberOfCertificates());

		List<CertificateToken> list = ccc.get(CERT.getSubjectX500Principal());
		assertEquals(1, list.size());
		assertEquals(CERT, list.get(0));

		list = ccc.get(CERT.getIssuerX500Principal());
		assertEquals(0, list.size());
	}

}
