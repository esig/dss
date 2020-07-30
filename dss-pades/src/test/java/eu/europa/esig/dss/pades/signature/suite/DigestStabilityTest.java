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
package eu.europa.esig.dss.pades.signature.suite;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.security.MessageDigest;
import java.util.Calendar;
import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.utils.Utils;

/**
 * This class checks if the getDataToSign result is equals when passing the same
 * parameters
 *
 */
public class DigestStabilityTest extends PKIFactoryAccess {

	private DSSPrivateKeyEntry privateKeyEntry;

	@BeforeEach
	public void init() {
		privateKeyEntry = getPrivateKeyEntry();
	}

	@Test
	public void testTwiceGetDataToSignReturnsSameDigest() throws Exception {

		DSSDocument toBeSigned = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"), "sample.pdf", MimeType.PDF);

		Date signingDate = new Date();

		ToBeSigned dataToSign1 = getDataToSign(toBeSigned, privateKeyEntry, signingDate);
		ToBeSigned dataToSign2 = getDataToSign(toBeSigned, privateKeyEntry, signingDate);

		final MessageDigest messageDigest = DigestAlgorithm.SHA256.getMessageDigest();
		byte[] digest1 = messageDigest.digest(dataToSign1.getBytes());
		byte[] digest2 = messageDigest.digest(dataToSign2.getBytes());

		assertEquals(Utils.toBase64(digest1), Utils.toBase64(digest2));
	}

	@Test
	public void differentDocumentGetDifferentDigest() throws Exception {
		DSSDocument toBeSigned1 = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"), "sample.pdf", MimeType.PDF);
		DSSDocument toBeSigned2 = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"), "doc.pdf", MimeType.PDF);

		Date signingDate = new Date();

		ToBeSigned dataToSign1 = getDataToSign(toBeSigned1, privateKeyEntry, signingDate);
		ToBeSigned dataToSign2 = getDataToSign(toBeSigned2, privateKeyEntry, signingDate);

		final MessageDigest messageDigest = DigestAlgorithm.SHA256.getMessageDigest();
		byte[] digest1 = messageDigest.digest(dataToSign1.getBytes());
		byte[] digest2 = messageDigest.digest(dataToSign2.getBytes());

		assertNotEquals(Utils.toBase64(digest1), Utils.toBase64(digest2));
	}

	@Test
	public void differentSigningDateGetDifferentDigest() throws Exception {
		DSSDocument toBeSigned = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"), "sample.pdf", MimeType.PDF);

		Calendar calendar = Calendar.getInstance();

		Date firstTime = calendar.getTime();
		ToBeSigned dataToSign1 = getDataToSign(toBeSigned, privateKeyEntry, firstTime);

		calendar.add(Calendar.MILLISECOND, 1);

		Date secondTime = calendar.getTime();
		ToBeSigned dataToSign2 = getDataToSign(toBeSigned, privateKeyEntry, secondTime);

		final MessageDigest messageDigest = DigestAlgorithm.SHA256.getMessageDigest();
		byte[] digest1 = messageDigest.digest(dataToSign1.getBytes());
		byte[] digest2 = messageDigest.digest(dataToSign2.getBytes());

		assertNotEquals("Digests must be different (Date1:" + firstTime + " / Date2:" + secondTime + ")", Utils.toBase64(digest1),
				Utils.toBase64(digest2));
	}

	private ToBeSigned getDataToSign(DSSDocument toBeSigned, DSSPrivateKeyEntry privateKeyEntry, Date signingDate) {

		DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service = new PAdESService(getOfflineCertificateVerifier());

		PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
		signatureParameters.bLevel().setSigningDate(signingDate);
		signatureParameters.setSigningCertificate(privateKeyEntry.getCertificate());
		signatureParameters.setCertificateChain(privateKeyEntry.getCertificateChain());
		signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

		return service.getDataToSign(toBeSigned, signatureParameters);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
