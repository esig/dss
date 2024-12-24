/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.token;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.security.KeyStore.PasswordProtection;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;

class Pkcs12SignatureTokenTest {

	@Test
	void testPkcs12() throws IOException {
		try (Pkcs12SignatureToken signatureToken = new Pkcs12SignatureToken("src/test/resources/user_a_rsa.p12",
				new PasswordProtection("password".toCharArray()))) {
			assertNotNull(signatureToken);

			List<DSSPrivateKeyEntry> keys = signatureToken.getKeys();
			assertFalse(keys.isEmpty());

			KSPrivateKeyEntry dssPrivateKeyEntry = (KSPrivateKeyEntry) keys.get(0);
			assertNotNull(dssPrivateKeyEntry);
			assertNotNull(dssPrivateKeyEntry.getAlias());

			DSSPrivateKeyEntry entry = signatureToken.getKey(dssPrivateKeyEntry.getAlias(),
					new PasswordProtection("password".toCharArray()));
			assertNotNull(entry);
			assertNotNull(entry.getCertificate());
			assertNotNull(entry.getCertificateChain());
			assertNotNull(entry.getEncryptionAlgorithm());

			ToBeSigned toBeSigned = new ToBeSigned("Hello world".getBytes("UTF-8"));
			SignatureValue signValue = signatureToken.sign(toBeSigned, DigestAlgorithm.SHA256, entry);
			assertNotNull(signValue);
			assertNotNull(signValue.getAlgorithm());
			assertNotNull(signValue.getValue());
		}
	}

	@Test
	void wrongPassword() throws IOException {
		PasswordProtection passwordProtection = new PasswordProtection("wrong password".toCharArray());
		Exception exception = assertThrows(DSSException.class,
				() -> new Pkcs12SignatureToken("src/test/resources/user_a_rsa.p12", passwordProtection));
		assertEquals("Unable to instantiate KeyStoreSignatureTokenConnection", exception.getMessage());
	}

}
