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
package eu.europa.esig.dss.model;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

class DigestAlgorithmParameterizedTest {

	private static Collection<DigestAlgorithm> data() {
		// digest algorithms which are supported by the JVM
		// other algorithms require BC,...
		return Arrays.asList(DigestAlgorithm.SHA1, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512, DigestAlgorithm.MD2,
				DigestAlgorithm.MD5);
	}

	@ParameterizedTest(name = "Digest {index} : {0}")
	@MethodSource("data")
	void getMessageDigest(DigestAlgorithm digestAlgo) throws NoSuchAlgorithmException {
		MessageDigest md = digestAlgo.getMessageDigest();
		assertNotNull(md);
		assertNotNull(md.digest(new byte[] { 1, 2, 3 }));
	}

}
