/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DSSASN1UtilsTest {
	
	private static CertificateToken certificateWithAIA;

	private static CertificateToken certificateOCSP;

	@BeforeAll
	static void init() {
		certificateWithAIA = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
		assertNotNull(certificateWithAIA);

		certificateOCSP = DSSUtils.loadCertificateFromBase64EncodedString(
				"MIIEXjCCAkagAwIBAgILBAAAAAABWLd6HkYwDQYJKoZIhvcNAQELBQAwMzELMAkGA1UEBhMCQkUxEzARBgNVBAMTCkNpdGl6ZW4gQ0ExDzANBgNVBAUTBjIwMTYzMTAeFw0xNjEyMTAxMTAwMDBaFw0xODAxMjkxMTAwMDBaMC4xHzAdBgNVBAMTFkJlbGdpdW0gT0NTUCBSZXNwb25kZXIxCzAJBgNVBAYTAkJFMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzD0B0c4gBx/wumeE2l/Wcz5FoMSUIuRNIySH2pJ3yfKR/u/FWCOzcrJvDMdmgzR33zGb4/fZel9YlI6xcN08Yd7GkP0/WtbHUhGUPERV76Vvyrk2K/EH/IG2gtxYB+7pkA/ZZycdyjc4IxHzBOiGofP9lDkPD05GSqI7MjVf6sNkZSnHcQSKwkaCGhAshJMjHzShEsSzOgX9kXceBFPTt6Hd2prVmnMTyAwURbQ6gFHbgfxB8JLMya95U6391nGQC66ScH1GhIwd9KSn+yBY0cazJ3nIrc8wd0yGYBgPK78jN3MvAsb1ydfs7kE+Wf95z9oRMiw62Glxh/ksLS/tTQIDAQABo3gwdjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFBgKRBywCTroyvAErr7p657558Y9MBMGA1UdJQQMMAoGCCsGAQUFBwMJMB8GA1UdIwQYMBaAFM6Al2fQrdlOxJlqgCcikM0RNRCHMA8GCSsGAQUFBzABBQQCBQAwDQYJKoZIhvcNAQELBQADggIBAFuZrqcwt23UiiJdRst66MEBRyKbgPsQM81Uq4FVrAnV8z3l8DDUv+A29KzCPO0GnHSatqA7DNhhMzoBRC42PqCpuvrj8VEWHd43AuPOLaikE04a5tVh6DgW8b00s6Yyf/PuDHCsg2C2MqY71MUR9GcnI7ngR2SyWQGpbsf/wfjujNxEB0+SOwMDTgIAikaueHGZbYkwvlRpL6wm2ENvrE8OvKt7NlNsaWJ4KtQo0QS5Ku+Y2BDA3bX+g8eNLQkaXTycgL4X3MyE5pBOl1OW3KOjJdfyLF+Sii+JKjNf8ZQWk0xvkBEI+nhCzDXhtKAcrkTKlXE25MiUnYoRsXkXgrzYftxAMxvFOXJji/hnX5Fe/3SBAHaE+jU6yC5nk6Q9ERii8mL0nHouMlZWSiAuXtlZDFrzwtLD2ITBECe4X60BDQfb/caO2u3HcWoG1AOvGxfQB0cMmP2njCdDf8UOqryiyky4t7Jj3ghOvETjWlwMw5ObhZ8yj8p6qFAt7+EVJfpUc1gDAolS/hJoLzohbL5LnCAnUAWsFpvG3qW1ky+X0MePXi6q/boqj2tcC4IDdsYS6RHPBvzl5+yLDccrGx1s/7vQYTMNyX0dYZzuxFZxx0bttWfjqLz3hFHlAEVmLCyUkSz761CbaT9u/G4tPP4Q8ApFfSskPI57lbLWIcwP");
		assertNotNull(certificateOCSP);
	}

	@Test
	void getDigestSignaturePolicy() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/signature-policy-example.der");
		byte[] policyBytes = Utils.toByteArray(fis);
		Utils.closeQuietly(fis);

		byte[] signaturePolicyDigest = DSSASN1Utils.getAsn1SignaturePolicyDigest(DigestAlgorithm.SHA256, policyBytes);
		String hexSignaturePolicyDigest = Utils.toHex(signaturePolicyDigest);

		assertEquals("fe71e01aedd99f444238602d4e98f47bbab405c58c0e3811b9511dcd58c3c983", hexSignaturePolicyDigest);
	}

	@Test
	void getSKI() {
		CertificateToken c1 = DSSUtils.loadCertificateFromBase64EncodedString(
				"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");
		CertificateToken c2 = DSSUtils.loadCertificateFromBase64EncodedString(
				"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");
		
		byte[] fixedSkiC1 = DSSASN1Utils.computeSkiFromCert(c1);
		byte[] fixedSkiC2 = DSSASN1Utils.computeSkiFromCert(c2);
		
		assertArrayEquals(fixedSkiC1, fixedSkiC2);
	}

	@Test
	void getCertificateHolder() {
		CertificateToken token = DSSUtils.loadCertificate(new File("src/test/resources/ec.europa.eu.crt"));
		X509CertificateHolder certificateHolder = DSSASN1Utils.getX509CertificateHolder(token);
		assertNotNull(certificateHolder);
		CertificateToken token2 = DSSASN1Utils.getCertificate(certificateHolder);
		assertEquals(token, token2);
	}

	@Test
	void getSubjectCommonName() {
		assertEquals("tts.luxtrust.lu", DSSASN1Utils.getSubjectCommonName(certificateWithAIA));
	}

	@Test
	void getHumanReadableName() {
		assertEquals("tts.luxtrust.lu", DSSASN1Utils.getHumanReadableName(certificateWithAIA));
	}

	@Test
	void getIssuerSerialFromCert() {
		IssuerSerial issuerSerial = DSSASN1Utils.getIssuerSerial(certificateWithAIA);
		assertNotNull(issuerSerial);
		assertNotNull(issuerSerial.getIssuer());
		assertNotNull(issuerSerial.getSerial());
	}

	@Test
	void getAlgorithmIdentifier() {
		assertNotNull(DSSASN1Utils.getAlgorithmIdentifier(DigestAlgorithm.SHA256));
	}
	
	@Test
	void getIssuerInfo() {
		String issuerV2base64 = "MFYwUaRPME0xEDAOBgNVBAMMB2dvb2QtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVQIBCg==";
		IssuerSerial issuerInfo = DSSASN1Utils.getIssuerSerial(Utils.fromBase64(issuerV2base64));
		assertNotNull(issuerInfo);
		assertNotNull(issuerInfo.getIssuer());
		assertNotNull(issuerInfo.getSerial());
	}

	@Test
	void x500PrincipalAreEquals() {
		String issuerName1 = "CN=ESTEID-SK 2015,organizationIdentifier=NTREE-10747013,O=AS Sertifitseerimiskeskus,C=EE";
		String issuerName2 = "CN=ESTEID-SK 2015,2.5.4.97=#0C0E4E545245452D3130373437303133,O=AS Sertifitseerimiskeskus,C=EE";
		String issuerName3 = "2.5.4.97=#0C0E4E545245452D3130373437303133,O=AS Sertifitseerimiskeskus,C=EE,CN=ESTEID-SK 2015";
		String issuerName4 = "2.5.4.97=#0C0E4E545245452D3130373437303133,O=AS Sertifitseerimiskeskus,C=BE,CN=ESTEID-SK 2015";
		String issuerName5 = "2.5.4.97=#0C0E4E545245452D3130373437303133,O=AS Sertifitseerimiskeskus,CN=ESTEID-SK 2015";
		X500Principal x500Principal1 = DSSUtils.getX500PrincipalOrNull(issuerName1);
		assertNotNull(x500Principal1);
		X500Principal x500Principal2 = DSSUtils.getX500PrincipalOrNull(issuerName2);
		assertNotNull(x500Principal2);
		X500Principal x500Principal3 = DSSUtils.getX500PrincipalOrNull(issuerName3);
		assertNotNull(x500Principal3);
		X500Principal x500Principal4 = DSSUtils.getX500PrincipalOrNull(issuerName4);
		assertNotNull(x500Principal4);
		X500Principal x500Principal5 = DSSUtils.getX500PrincipalOrNull(issuerName5);
		assertNotNull(x500Principal5);
        assertTrue(DSSASN1Utils.x500PrincipalAreEquals(x500Principal1, x500Principal2));
        assertTrue(DSSASN1Utils.x500PrincipalAreEquals(x500Principal1, x500Principal3));
        assertFalse(DSSASN1Utils.x500PrincipalAreEquals(x500Principal1, x500Principal4));
        assertFalse(DSSASN1Utils.x500PrincipalAreEquals(x500Principal5, x500Principal4));
		assertFalse(DSSASN1Utils.x500PrincipalAreEquals(x500Principal4, x500Principal5));
	}

	@Test
	void getDEREncoded() throws IOException, CMSException, TSPException {

		String berEncodedTST = "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";
		byte[] originalBinaries = Utils.fromBase64(berEncodedTST);

		try (ByteArrayInputStream bais = new ByteArrayInputStream(originalBinaries)) {
			CMSSignedData cms = new CMSSignedData(bais);
			TimeStampToken tst = new TimeStampToken(cms);

			byte[] defaultEncoded = tst.getEncoded(ASN1Encoding.BER);
			String defaultEncodedBase64 = Utils.toBase64(defaultEncoded);
			assertEquals(berEncodedTST, defaultEncodedBase64);

			ASN1InputStream asn1IS = new ASN1InputStream(defaultEncoded);
			ASN1Primitive firstObject = asn1IS.readObject();
			byte[] expectedBinaries = firstObject.getEncoded(ASN1Encoding.DER);
			byte[] berBinaries = firstObject.getEncoded(ASN1Encoding.BER);
			asn1IS.close();

			assertArrayEquals(originalBinaries, berBinaries);

			byte[] derEncoded = DSSASN1Utils.getDEREncoded(tst);
			assertNotNull(derEncoded); 
			String derEncodedBase64 = Utils.toBase64(derEncoded);
			
			assertNotEquals(derEncodedBase64, defaultEncodedBase64);
			assertArrayEquals(expectedBinaries, derEncoded);

			asn1IS = new ASN1InputStream(derEncoded);
			DERSequence derSequence = new DERSequence(asn1IS.readObject());
			assertNotNull(derSequence);
			asn1IS.close();

			TimeStampToken rebuiltTST = new TimeStampToken(new CMSSignedData(derEncoded));
			assertNotNull(rebuiltTST);
		}
	}

	@Test
	void convertSignatureValueTest() {
		assertSignatureValueValid(Utils.fromBase64("MEQCIEJNA0AElH/vEH9xLxvqrwCqh+yUh9ACL2vU/2eObRbTAiAxTLSWSioJrfSwPkKcypf+KCHvMGdwZbRWQHnZN2sDnQ=="), true);
		assertSignatureValueValid(Utils.fromHex("2B9099C9885DDB5BFDA2E9634905B9A63E7E3A6EC87BDC0A89014716B23F00B0AD787FC8D0DCF28F007E7DEC097F30DA892BE2AC61D90997DCDF05740E4D5B0C"), false);
		assertSignatureValueValid(Utils.fromHex("947b79069e6a1e3316ec15d696649a4b67c6c188df9bc05458f3b0b94907f3fb52522d4cae24a75735969cff556b1476a5ccbe37ca65a928782c14f299f3b2d3"), false);
		assertSignatureValueValid(Utils.fromHex("28a1583e58e93a661322f776618d83b023bdc52b2e909cf9d53030b9260ed667b588fd39eeee5b1b55523a7e71cb4187d8b1bbf56c1581fc845863157d279cf5"), false);
		assertSignatureValueValid(Utils.fromHex("dd8fc5414eda2920d347f3d3f9f604fcf09392a8ce3807f6f87d006cf8ed1959075af8abbb030e6990da52fe49c93486a4b98bb2e18e0f84095175eddabfbb96"), false);
		assertSignatureValueValid(Utils.fromHex("1daf408ead014bba9f243849ece308b31f898e1ce97b54a78b3c15eb103fa8a1c87bdd97fdfc4cb56a7e1e5650dee2ebfff0b56d5a2ca0338e6ed59689e27ae1323f32b0f93b41987a816c93c00462c68c609692084dbced7308a8a66f0365ee5b7b272273e8abd4ddd4a49d2fd67964bc8c757114791446b9716f3b7f551608"), false);
		assertSignatureValueValid(Utils.fromHex("0d2fc9f18d816e9054af943c392dd46f09da71521de9bd98d765e170f12eb086d3d0f9754105001ed2e703d7290ac967642bc70bdd7a96b5c2b8e3d4b503b80e"), false);
		assertSignatureValueValid(Utils.fromHex("065a15bd4fec67a2a302d9d3ec679cb8f298f9d6a1d855d3dbf39b3f2fa7ea461e437d9542c4a9527afe5e78c1412937f0dbb05a78380cfb2e1bf6eff944581a"), false);
		assertSignatureValueValid(Utils.fromHex("f322898717aada9b027855848fa6ec5c4bf84d67a70f0ecbafea9dc90fc1d4f0901325766b199bdcfce1f99a54f0b72e71d740b355fff84a5873fd36c439236e"), false);
		assertSignatureValueValid(Utils.fromHex("B003267151210F7D8D1A747EEC73A0185CC0E848BF885A9DDE061AB5FB19FB3B6249F8B7B84432738EE80DDAB9654DEA5C4DAB2EC34A5EC8DB17E3DFBF577521"), false);
		assertSignatureValueValid(Utils.fromHex("C511529B789F64466FE1D524AF9279BEED2F12429798FE0B920F9784A6EBB6400081949A7EE84803E823263CD528F5CE503593F00010191D382B092338AF2E96"), false);
	}

	private void assertSignatureValueValid(byte[] signatureValue, boolean asn1Encoded) {
		assertEquals(asn1Encoded, DSSASN1Utils.isAsn1EncodedSignatureValue(signatureValue));

		byte[] encodedSignatureValue;
		if (asn1Encoded) {
			encodedSignatureValue = DSSASN1Utils.toPlainDSASignatureValue(signatureValue);
		} else {
			encodedSignatureValue = DSSASN1Utils.toStandardDSASignatureValue(signatureValue);
		}
		assertEquals(!asn1Encoded, DSSASN1Utils.isAsn1EncodedSignatureValue(encodedSignatureValue));

		byte[] decodedSignatureValue;
		if (asn1Encoded) {
			decodedSignatureValue = DSSASN1Utils.toStandardDSASignatureValue(encodedSignatureValue);
		} else {
			decodedSignatureValue = DSSASN1Utils.toPlainDSASignatureValue(encodedSignatureValue);
		}
		assertArrayEquals(signatureValue, decodedSignatureValue);
	}

	@Test
	void isAsn1EncodedTest() throws Exception {
		assertTrue(DSSASN1Utils.isAsn1Encoded(new DERUTCTime(new Date()).getEncoded()));
		assertTrue(DSSASN1Utils.isAsn1Encoded(DSSASN1Utils.getDEREncoded(new DERUTCTime(new Date()))));
		assertTrue(DSSASN1Utils.isAsn1Encoded(new DERUTF8String("Hello World!").getEncoded()));

		ASN1EncodableVector asn1EncodableVector = new ASN1EncodableVector();
		asn1EncodableVector.add(new DERUTF8String("Hello World!"));
		assertTrue(DSSASN1Utils.isAsn1Encoded(new DERSet(asn1EncodableVector).getEncoded()));
		assertTrue(DSSASN1Utils.isAsn1Encoded(new DERSequence(asn1EncodableVector).getEncoded()));

		assertFalse(DSSASN1Utils.isAsn1Encoded("Hello World!".getBytes()));
		assertFalse(DSSASN1Utils.isAsn1Encoded(new byte[] { '1', 'A', 'B' }));
		assertFalse(DSSASN1Utils.isAsn1Encoded(new Date().toString().getBytes()));
		assertFalse(DSSASN1Utils.isAsn1Encoded(DSSUtils.EMPTY_BYTE_ARRAY));
		assertFalse(DSSASN1Utils.isAsn1Encoded(null));
	}

	@Test
	void getStringTest() {
		assertNull(DSSASN1Utils.getString(null));
		assertEquals("", DSSASN1Utils.getString(new DERUTF8String("")));
		assertEquals("Hello World!", DSSASN1Utils.getString(new DERUTF8String("Hello World!")));
		assertEquals("Hello World!", DSSASN1Utils.getString(new DERPrintableString("Hello World!")));
		assertEquals("#1c0c48656c6c6f20576f726c6421", DSSASN1Utils.getString(
				new DERUniversalString("Hello World!".getBytes(StandardCharsets.UTF_8))));
		assertEquals("#06042a030405", DSSASN1Utils.getString(new ASN1ObjectIdentifier("1.2.3.4.5")));

		DERSequence derSequence = new DERSequence(new ASN1Encodable[] {new DERUTF8String("Hello World!"), new DERUTF8String("Bye World!")});
		assertEquals("#301a0c0c48656c6c6f20576f726c64210c0a42796520576f726c6421", DSSASN1Utils.getString(derSequence));
	}

}
