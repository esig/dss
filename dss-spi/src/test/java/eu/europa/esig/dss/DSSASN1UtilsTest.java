package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.X509CRL;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.junit.BeforeClass;
import org.junit.Test;

import eu.europa.esig.dss.x509.CertificateToken;

public class DSSASN1UtilsTest {

	private static CertificateToken certificateWithAIA;

	@BeforeClass
	public static void init() {
		certificateWithAIA = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
		assertNotNull(certificateWithAIA);
	}

	@Test
	public void getDigestSignaturePolicy() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/signature-policy-example.der");
		byte[] policyBytes = IOUtils.toByteArray(fis);
		IOUtils.closeQuietly(fis);

		byte[] signaturePolicyDigest = DSSASN1Utils.getAsn1SignaturePolicyDigest(DigestAlgorithm.SHA256, policyBytes);
		String hexSignaturePolicyDigest = Hex.encodeHexString(signaturePolicyDigest);

		assertEquals("fe71e01aedd99f444238602d4e98f47bbab405c58c0e3811b9511dcd58c3c983", hexSignaturePolicyDigest);
	}

	@Test
	public void getPolicies() {
		List<String> policyIdentifiers = DSSASN1Utils.getPolicyIdentifiers(certificateWithAIA);
		assertTrue(CollectionUtils.isNotEmpty(policyIdentifiers));
		assertTrue(policyIdentifiers.contains("1.3.171.1.1.10.8.1"));
	}

	@Test
	public void getQCStatementsIdList() {
		List<String> qcStatementsIdList = DSSASN1Utils.getQCStatementsIdList(certificateWithAIA);
		assertTrue(CollectionUtils.isEmpty(qcStatementsIdList));

		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		qcStatementsIdList = DSSASN1Utils.getQCStatementsIdList(certificate);
		assertTrue(CollectionUtils.isNotEmpty(qcStatementsIdList));
		assertTrue(qcStatementsIdList.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue.getId()));
	}

	@Test
	public void getSKI() {
		byte[] ski = DSSASN1Utils.getSki(certificateWithAIA);
		assertEquals("4c4c4cfcacace6bb", Hex.encodeHexString(ski));
	}

	@Test
	public void getExpiredCertsOnCRL() throws Exception {
		X509CRL x509crl = DSSUtils.loadCRL(new FileInputStream("src/test/resources/crl/crl_with_expiredCertsOnCRL_extension.crl"));
		assertNotNull(DSSASN1Utils.getExpiredCertsOnCRL(x509crl));

		x509crl = DSSUtils.loadCRL(new FileInputStream("src/test/resources/crl/LTRCA.crl"));
		assertNull(DSSASN1Utils.getExpiredCertsOnCRL(x509crl));
	}
}
