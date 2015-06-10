package eu.europa.esig.dss;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.X509CRL;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.junit.BeforeClass;
import org.junit.Test;

import eu.europa.esig.dss.client.http.NativeHTTPDataLoader;
import eu.europa.esig.dss.x509.CertificateToken;

public class DSSUtilsTest {

	private static CertificateToken certificateWithAIA;

	@BeforeClass
	public static void init() {
		certificateWithAIA = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
		assertNotNull(certificateWithAIA);
	}

	@Test
	public void getPolicies() {
		List<String> policyIdentifiers = DSSUtils.getPolicyIdentifiers(certificateWithAIA.getCertificate());
		assertTrue(CollectionUtils.isNotEmpty(policyIdentifiers));
		assertTrue(policyIdentifiers.contains("1.3.171.1.1.10.8.1"));
	}

	@Test
	public void getQCStatementsIdList() {
		List<String> qcStatementsIdList = DSSUtils.getQCStatementsIdList(certificateWithAIA.getCertificate());
		assertTrue(CollectionUtils.isEmpty(qcStatementsIdList));

		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		qcStatementsIdList = DSSUtils.getQCStatementsIdList(certificate.getCertificate());
		assertTrue(CollectionUtils.isNotEmpty(qcStatementsIdList));
		assertTrue(qcStatementsIdList.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue.getId()));
	}

	@Test
	public void testLoadIssuer() {
		CertificateToken issuer = DSSUtils.loadIssuerCertificate(certificateWithAIA, new NativeHTTPDataLoader());
		assertNotNull(issuer);
		assertTrue(certificateWithAIA.isSignedBy(issuer));
	}

	@Test
	public void testLoadIssuerEmptyDataLoader() {
		assertNull(DSSUtils.loadIssuerCertificate(certificateWithAIA, null));
	}

	@Test
	public void testLoadIssuerNoAIA() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
		assertNull(DSSUtils.loadIssuerCertificate(certificate, new NativeHTTPDataLoader()));
	}

	@Test
	public void convertToPEM() {
		String convertToPEM = DSSUtils.convertToPEM(certificateWithAIA);
		CertificateToken certificate = DSSUtils.loadCertificate(convertToPEM.getBytes());
		assertTrue(certificate.equals(certificateWithAIA));
	}

	@Test
	public void loadCrl() throws Exception {
		X509CRL crl = DSSUtils.loadCRL(new FileInputStream("src/test/resources/crl/belgium2.crl"));
		assertNotNull(crl);
	}
}
