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

import static org.junit.Assert.assertNotEquals;

import java.util.Arrays;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.AbstractSignatureParameters;
import eu.europa.esig.dss.test.gen.CertificateService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;

@RunWith(Parameterized.class)
public class DeterministicIdGenerationTest {

	private static SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RSA_SHA256;

	private static DSSPrivateKeyEntry privateKeyEntry;

	@Parameters
	public static List<Object[]> data() {
		return Arrays.asList(new Object[10][0]);
	}

	public DeterministicIdGenerationTest() {
	}

	@BeforeClass
	public static void setUp() throws Exception {
		CertificateService certificateService = new CertificateService();
		privateKeyEntry = certificateService.generateCertificateChain(signatureAlgorithm);
	}

	@Test
	public void testDifferentDeterministicId() throws InterruptedException {

		SignatureParameters params = new SignatureParameters();
		params.setSigningCertificate(privateKeyEntry.getCertificate());
		String deterministicId1 = params.getDeterministicId();

		Thread.sleep(1); // 1 millisecond

		params = new SignatureParameters();
		params.setSigningCertificate(privateKeyEntry.getCertificate());
		String deterministicId2 = params.getDeterministicId();

		assertNotEquals(deterministicId1, deterministicId2);

	}

	private class SignatureParameters extends AbstractSignatureParameters {

	}
}
