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
package eu.europa.esig.dss.pades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.io.File;
import java.security.MessageDigest;
import java.util.Date;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.FileDocument;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.SignaturePackaging;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

/**
 * This class checks if the getDataToSign result is equals when passing the same
 * parameters
 *
 */
public class DigestStabilityTest {

	@Test
	public void testTwiceGetDataToSignReturnsSameDigest() throws Exception {
		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.pdf"));

		CertificateService certificateService = new CertificateService();
		DSSPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		Date signingDate = new Date();

		ToBeSigned dataToSign1 = getDataToSign(toBeSigned, privateKeyEntry, signingDate);
		ToBeSigned dataToSign2 = getDataToSign(toBeSigned, privateKeyEntry, signingDate);

		final MessageDigest messageDigest = MessageDigest.getInstance(DigestAlgorithm.SHA256.getOid().getId());
		byte[] digest1 = messageDigest.digest(dataToSign1.getBytes());
		byte[] digest2 = messageDigest.digest(dataToSign2.getBytes());

		assertEquals(Base64.encodeBase64String(digest1), Base64.encodeBase64String(digest2));
	}

	@Test
	public void differentDocumentGetDifferentDigest() throws Exception {
		DSSDocument toBeSigned1 = new FileDocument(new File("src/test/resources/sample.pdf"));
		DSSDocument toBeSigned2 = new FileDocument(new File("src/test/resources/validation/pades-5-signatures-and-1-document-timestamp.pdf"));

		CertificateService certificateService = new CertificateService();
		DSSPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		Date signingDate = new Date();

		ToBeSigned dataToSign1 = getDataToSign(toBeSigned1, privateKeyEntry, signingDate);
		ToBeSigned dataToSign2 = getDataToSign(toBeSigned2, privateKeyEntry, signingDate);

		final MessageDigest messageDigest = MessageDigest.getInstance(DigestAlgorithm.SHA256.getOid().getId());
		byte[] digest1 = messageDigest.digest(dataToSign1.getBytes());
		byte[] digest2 = messageDigest.digest(dataToSign2.getBytes());

		assertNotEquals(Base64.encodeBase64String(digest1), Base64.encodeBase64String(digest2));
	}

	@Test
	public void differentSigningDateGetDifferentDigest() throws Exception {
		DSSDocument toBeSigned = new FileDocument(new File("src/test/resources/sample.pdf"));

		CertificateService certificateService = new CertificateService();
		DSSPrivateKeyEntry privateKeyEntry = certificateService.generateCertificateChain(SignatureAlgorithm.RSA_SHA256);

		Date signingDate = new Date();
		ToBeSigned dataToSign1 = getDataToSign(toBeSigned, privateKeyEntry, signingDate);

		signingDate = new Date();
		ToBeSigned dataToSign2 = getDataToSign(toBeSigned, privateKeyEntry, signingDate);

		final MessageDigest messageDigest = MessageDigest.getInstance(DigestAlgorithm.SHA256.getOid().getId());
		byte[] digest1 = messageDigest.digest(dataToSign1.getBytes());
		byte[] digest2 = messageDigest.digest(dataToSign2.getBytes());

		assertNotEquals(Base64.encodeBase64String(digest1), Base64.encodeBase64String(digest2));
	}

	private ToBeSigned getDataToSign(DSSDocument toBeSigned, DSSPrivateKeyEntry privateKeyEntry, Date signingDate) {

		DocumentSignatureService<PAdESSignatureParameters> service = new PAdESService(new CommonCertificateVerifier());

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		return service.getDataToSign(toBeSigned, signatureParameters);
	}

}
