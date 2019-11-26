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
package eu.europa.esig.dss.model;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public class DigestAlgorithmParameterizedBouncyCastleTest {

	private Provider provider = new BouncyCastleProvider();

	@ParameterizedTest(name = "Digest {index} : {0}")
	@EnumSource(DigestAlgorithm.class)
	public void getMessageDigest(DigestAlgorithm digestAlgo) throws NoSuchAlgorithmException {
		MessageDigest md = digestAlgo.getMessageDigest(provider);
		assertNotNull(md);
		assertNotNull(md.digest(new byte[] { 1, 2, 3 }));
	}

}
