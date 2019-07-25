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
package eu.europa.esig.dss;

import static org.junit.Assert.assertNotNull;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

@RunWith(Parameterized.class)
public class DigestAlgorithmParameterizedTest {

	private final DigestAlgorithm digestAlgo;

	@Parameters(name = "Digest {index} : {0}")
	public static Collection<DigestAlgorithm> data() {
		// digest algorithms which are supported by the JVM
		// other algorithms require BC,...
		return Arrays.asList(DigestAlgorithm.SHA1, DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512, DigestAlgorithm.MD2,
				DigestAlgorithm.MD5);
	}

	public DigestAlgorithmParameterizedTest(DigestAlgorithm digestAlgo) {
		this.digestAlgo = digestAlgo;
	}

	@Test
	public void getMessageDigest() throws NoSuchAlgorithmException {
		MessageDigest md = digestAlgo.getMessageDigest();
		assertNotNull(md);
		assertNotNull(md.digest(new byte[] { 1, 2, 3 }));
	}

}
