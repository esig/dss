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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.KeyStore.PasswordProtection;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.RemoteKeyEntry;
import eu.europa.esig.dss.SignatureValue;
import eu.europa.esig.dss.ToBeSigned;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;

public class RemoteSignatureTokenConnectionImplTest {

	@Test
	public void testRemoteSigning() throws IOException {

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
		ToBeSigned toBeSigned = new ToBeSigned(new byte[] {1,2,3,4,5});
		SignatureValue signatureValue = exposedToken.sign(toBeSigned, DigestAlgorithm.SHA256,
				remoteKeyEntry.getAlias());
		assertNotNull(signatureValue);
		assertNotNull(signatureValue.getValue());
		assertEquals(SignatureAlgorithm.RSA_SHA256, signatureValue.getAlgorithm());
	}

}
