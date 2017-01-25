package eu.europa.esig.dss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.util.List;

import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.BeforeClass;
import org.junit.Test;

import eu.europa.esig.dss.utils.Utils;
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
		byte[] policyBytes = Utils.toByteArray(fis);
		Utils.closeQuietly(fis);

		byte[] signaturePolicyDigest = DSSASN1Utils.getAsn1SignaturePolicyDigest(DigestAlgorithm.SHA256, policyBytes);
		String hexSignaturePolicyDigest = Utils.toHex(signaturePolicyDigest);

		assertEquals("fe71e01aedd99f444238602d4e98f47bbab405c58c0e3811b9511dcd58c3c983", hexSignaturePolicyDigest);
	}

	@Test
	public void getPolicies() {
		List<String> policyIdentifiers = DSSASN1Utils.getPolicyIdentifiers(certificateWithAIA);
		assertTrue(Utils.isCollectionNotEmpty(policyIdentifiers));
		assertTrue(policyIdentifiers.contains("1.3.171.1.1.10.8.1"));
	}

	@Test
	public void getQCStatementsIdList() {
		List<String> qcStatementsIdList = DSSASN1Utils.getQCStatementsIdList(certificateWithAIA);
		assertTrue(Utils.isCollectionEmpty(qcStatementsIdList));

		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		qcStatementsIdList = DSSASN1Utils.getQCStatementsIdList(certificate);
		assertTrue(Utils.isCollectionNotEmpty(qcStatementsIdList));
		assertTrue(qcStatementsIdList.contains(ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue.getId()));
	}

	@Test
	public void getSKI() {
		byte[] ski = DSSASN1Utils.getSki(certificateWithAIA);
		assertEquals("4c4c4cfcacace6bb", Utils.toHex(ski));

		CertificateToken certNoSKIextension = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIICaDCCAdSgAwIBAgIDDIOqMAoGBiskAwMBAgUAMG8xCzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjVSLUNBIDE6UE4wIhgPMjAwMDAzMjIwODU1NTFaGA8yMDA1MDMyMjA4NTU1MVowbzELMAkGA1UEBhMCREUxPTA7BgNVBAoUNFJlZ3VsaWVydW5nc2JlaMhvcmRlIGbIdXIgVGVsZWtvbW11bmlrYXRpb24gdW5kIFBvc3QxITAMBgcCggYBCgcUEwExMBEGA1UEAxQKNVItQ0EgMTpQTjCBoTANBgkqhkiG9w0BAQEFAAOBjwAwgYsCgYEAih5BUycfBpqKhU8RDsaSvV5AtzWeXQRColL9CH3t0DKnhjKAlJ8iccFtJNv+d3bh8bb9sh0maRSo647xP7hsHTjKgTE4zM5BYNfXvST79OtcMgAzrnDiGjQIIWv8xbfV1MqxxdtZJygrwzRMb9jGCAGoJEymoyzAMNG7tSdBWnUCBQDAAAABoxIwEDAOBgNVHQ8BAf8EBAMCAQYwCgYGKyQDAwECBQADgYEAOaK8ihVSBUcL2IdVBxZYYUKwMz5m7H3zqhN8W9w+iafWudH6b+aahkbENEwzg3C3v5g8nze7v7ssacQze657LHjP+e7ksUDIgcS4R1pU2eN16bjSP/qGPF3rhrIEHoK5nJULkjkZYTtNiOvmQ/+G70TXDi3Os/TwLlWRvu+7YLM=");
		assertNull(DSSASN1Utils.getSki(certNoSKIextension));

		assertNull(DSSASN1Utils.getSki(certNoSKIextension, false));
		assertNotNull(DSSASN1Utils.getSki(certNoSKIextension, true));
	}

	@Test
	public void getAccessLocation() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		List<String> ocspAccessLocations = DSSASN1Utils.getOCSPAccessLocations(certificate);
		assertEquals(1, Utils.collectionSize(ocspAccessLocations));
		assertEquals("http://ocsp.luxtrust.lu", ocspAccessLocations.get(0));
	}

	@Test
	public void getCAAccessLocations() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		List<String> caLocations = DSSASN1Utils.getCAAccessLocations(certificate);
		assertEquals(1, Utils.collectionSize(caLocations));
		assertEquals("http://ca.luxtrust.lu/LTQCA.crt", caLocations.get(0));
	}

	@Test
	public void getCrlUrls() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		List<String> crlUrls = DSSASN1Utils.getCrlUrls(certificate);
		assertEquals(1, Utils.collectionSize(crlUrls));
		assertEquals("http://crl.luxtrust.lu/LTQCA.crl", crlUrls.get(0));
	}

	@Test
	public void getCertificateHolder() {
		CertificateToken token = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		X509CertificateHolder certificateHolder = DSSASN1Utils.getX509CertificateHolder(token);
		assertNotNull(certificateHolder);
		CertificateToken token2 = DSSASN1Utils.getCertificate(certificateHolder);
		assertEquals(token, token2);
	}

}
