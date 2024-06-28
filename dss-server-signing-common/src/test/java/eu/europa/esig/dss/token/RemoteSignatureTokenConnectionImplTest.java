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
package eu.europa.esig.dss.token;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.ws.dto.DigestDTO;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.server.signing.common.RemoteSignatureTokenConnectionImpl;
import eu.europa.esig.dss.ws.server.signing.dto.RemoteKeyEntry;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore.PasswordProtection;
import java.security.Signature;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemoteSignatureTokenConnectionImplTest {

	@Test
	void testRemoteSigning() throws IOException {

		Pkcs12SignatureToken serverToken = new Pkcs12SignatureToken("src/test/resources/good-user.p12",
				new PasswordProtection("ks-password".toCharArray()));
		
		RemoteSignatureTokenConnectionImpl exposedToken = new RemoteSignatureTokenConnectionImpl();
		exposedToken.setToken(serverToken);
		
		List<RemoteKeyEntry> keys = exposedToken.getKeys();
		assertTrue(keys != null && keys.size() > 0);

		for (RemoteKeyEntry remoteKeyEntry : keys) {
			assertNotNull(remoteKeyEntry.getAlias());
			assertNotNull(remoteKeyEntry.getCertificate());
			assertNotNull(remoteKeyEntry.getCertificateChain());

			RemoteKeyEntry key = exposedToken.getKey(remoteKeyEntry.getAlias());
			assertEquals(remoteKeyEntry.getAlias(), key.getAlias());
			assertEquals(remoteKeyEntry.getEncryptionAlgo(), key.getEncryptionAlgo());
		}
		
		RemoteKeyEntry remoteKeyEntry = keys.get(0);
		ToBeSignedDTO toBeSigned = new ToBeSignedDTO(new byte[] {1,2,3,4,5});
		SignatureValueDTO signatureValue = exposedToken.sign(toBeSigned, DigestAlgorithm.SHA256,
				remoteKeyEntry.getAlias());
		assertNotNull(signatureValue);
		assertNotNull(signatureValue.getValue());
		assertEquals(SignatureAlgorithm.RSA_SHA256, signatureValue.getAlgorithm());

		try {
			Signature sig = Signature.getInstance(signatureValue.getAlgorithm().getJCEId());
			CertificateToken certificateToken = DSSUtils.loadCertificate(remoteKeyEntry.getCertificate().getEncodedCertificate());
			sig.initVerify(certificateToken.getPublicKey());
			sig.update(toBeSigned.getBytes());
			assertTrue(sig.verify(signatureValue.getValue()));
		} catch (GeneralSecurityException e) {
			Assertions.fail(e.getMessage());
		}
	}

	@Test
	void testRemoteSigningWithSignatureAlgorithm() throws IOException {

		Pkcs12SignatureToken serverToken = new Pkcs12SignatureToken("src/test/resources/good-user.p12",
				new PasswordProtection("ks-password".toCharArray()));

		RemoteSignatureTokenConnectionImpl exposedToken = new RemoteSignatureTokenConnectionImpl();
		exposedToken.setToken(serverToken);

		List<RemoteKeyEntry> keys = exposedToken.getKeys();
		assertTrue(keys != null && keys.size() > 0);

		for (RemoteKeyEntry remoteKeyEntry : keys) {
			assertNotNull(remoteKeyEntry.getAlias());
			assertNotNull(remoteKeyEntry.getCertificate());
			assertNotNull(remoteKeyEntry.getCertificateChain());

			RemoteKeyEntry key = exposedToken.getKey(remoteKeyEntry.getAlias());
			assertEquals(remoteKeyEntry.getAlias(), key.getAlias());
			assertEquals(remoteKeyEntry.getEncryptionAlgo(), key.getEncryptionAlgo());
		}

		RemoteKeyEntry remoteKeyEntry = keys.get(0);
		ToBeSignedDTO toBeSigned = new ToBeSignedDTO(new byte[] {1,2,3,4,5});
		SignatureValueDTO signatureValue = exposedToken.sign(
				toBeSigned, SignatureAlgorithm.RSA_SHA256, remoteKeyEntry.getAlias());
		assertNotNull(signatureValue);
		assertNotNull(signatureValue.getValue());
		assertEquals(SignatureAlgorithm.RSA_SHA256, signatureValue.getAlgorithm());

		try {
			Signature sig = Signature.getInstance(signatureValue.getAlgorithm().getJCEId());
			CertificateToken certificateToken = DSSUtils.loadCertificate(remoteKeyEntry.getCertificate().getEncodedCertificate());
			sig.initVerify(certificateToken.getPublicKey());
			sig.update(toBeSigned.getBytes());
			assertTrue(sig.verify(signatureValue.getValue()));
		} catch (GeneralSecurityException e) {
			Assertions.fail(e.getMessage());
		}
	}

	@Test
	void testRemoteSignDigest() throws IOException {

		Pkcs12SignatureToken serverToken = new Pkcs12SignatureToken("src/test/resources/good-user.p12",
				new PasswordProtection("ks-password".toCharArray()));

		RemoteSignatureTokenConnectionImpl exposedToken = new RemoteSignatureTokenConnectionImpl();
		exposedToken.setToken(serverToken);

		List<RemoteKeyEntry> keys = exposedToken.getKeys();
		assertTrue(keys != null && keys.size() > 0);

		for (RemoteKeyEntry remoteKeyEntry : keys) {
			assertNotNull(remoteKeyEntry.getAlias());
			assertNotNull(remoteKeyEntry.getCertificate());
			assertNotNull(remoteKeyEntry.getCertificateChain());

			RemoteKeyEntry key = exposedToken.getKey(remoteKeyEntry.getAlias());
			assertEquals(remoteKeyEntry.getAlias(), key.getAlias());
			assertEquals(remoteKeyEntry.getEncryptionAlgo(), key.getEncryptionAlgo());
		}

		RemoteKeyEntry remoteKeyEntry = keys.get(0);
		byte[] toBeSigned = {1, 2, 3, 4, 5};
		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, toBeSigned);
		byte[] encodedDigest = DSSUtils.encodeRSADigest(DigestAlgorithm.SHA256, digest);
		System.out.println(Base64.getEncoder().encodeToString(encodedDigest));
		DigestDTO digestDTO = new DigestDTO(DigestAlgorithm.SHA256, encodedDigest);
		SignatureValueDTO signatureValue = exposedToken.signDigest(digestDTO, remoteKeyEntry.getAlias());
		assertNotNull(signatureValue);
		assertNotNull(signatureValue.getValue());
		assertEquals(SignatureAlgorithm.RSA_SHA256, signatureValue.getAlgorithm());

		try {
			Signature sig = Signature.getInstance(signatureValue.getAlgorithm().getJCEId());
			CertificateToken certificateToken = DSSUtils.loadCertificate(remoteKeyEntry.getCertificate().getEncodedCertificate());
			sig.initVerify(certificateToken.getPublicKey());
			sig.update(toBeSigned);
			assertTrue(sig.verify(signatureValue.getValue()));
		} catch (GeneralSecurityException e) {
			Assertions.fail(e.getMessage());
		}
	}

	@Test
	void testRemoteSignDigestWithSignatureAlgorithm() throws IOException {

		Pkcs12SignatureToken serverToken = new Pkcs12SignatureToken("src/test/resources/good-user.p12",
				new PasswordProtection("ks-password".toCharArray()));

		RemoteSignatureTokenConnectionImpl exposedToken = new RemoteSignatureTokenConnectionImpl();
		exposedToken.setToken(serverToken);

		List<RemoteKeyEntry> keys = exposedToken.getKeys();
		assertTrue(keys != null && keys.size() > 0);

		for (RemoteKeyEntry remoteKeyEntry : keys) {
			assertNotNull(remoteKeyEntry.getAlias());
			assertNotNull(remoteKeyEntry.getCertificate());
			assertNotNull(remoteKeyEntry.getCertificateChain());

			RemoteKeyEntry key = exposedToken.getKey(remoteKeyEntry.getAlias());
			assertEquals(remoteKeyEntry.getAlias(), key.getAlias());
			assertEquals(remoteKeyEntry.getEncryptionAlgo(), key.getEncryptionAlgo());
		}

		RemoteKeyEntry remoteKeyEntry = keys.get(0);
		byte[] toBeSigned = {1, 2, 3, 4, 5};
		byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, toBeSigned);
		byte[] encodedDigest = DSSUtils.encodeRSADigest(DigestAlgorithm.SHA256, digest);
		DigestDTO digestDTO = new DigestDTO(DigestAlgorithm.SHA256, encodedDigest);
		SignatureValueDTO signatureValue = exposedToken.signDigest(
				digestDTO, SignatureAlgorithm.RSA_SHA256, remoteKeyEntry.getAlias());
		assertNotNull(signatureValue);
		assertNotNull(signatureValue.getValue());
		assertEquals(SignatureAlgorithm.RSA_SHA256, signatureValue.getAlgorithm());

		try {
			Signature sig = Signature.getInstance(signatureValue.getAlgorithm().getJCEId());
			CertificateToken certificateToken = DSSUtils.loadCertificate(remoteKeyEntry.getCertificate().getEncodedCertificate());
			sig.initVerify(certificateToken.getPublicKey());
			sig.update(toBeSigned);
			assertTrue(sig.verify(signatureValue.getValue()));
		} catch (GeneralSecurityException e) {
			Assertions.fail(e.getMessage());
		}
	}

}
