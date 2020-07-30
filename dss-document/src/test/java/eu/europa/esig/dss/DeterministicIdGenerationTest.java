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

import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.FileInputStream;
import java.util.Calendar;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;

import eu.europa.esig.dss.model.TimestampParameters;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;

public class DeterministicIdGenerationTest {

	private CertificateToken signingCert;

	public DeterministicIdGenerationTest() {
	}

	@BeforeEach
	public void setUp() throws Exception {
		signingCert = DSSUtils.loadCertificate(new FileInputStream("src/test/resources/certificates/ec.europa.eu.crt"));
	}

	@RepeatedTest(10)
	public void testDifferentDeterministicId() throws InterruptedException {

		Calendar calendar = Calendar.getInstance();

		SignatureParameters params = new SignatureParameters();
		params.setSigningCertificate(signingCert);
		params.bLevel().setSigningDate(calendar.getTime());
		String deterministicId1 = params.getDeterministicId();

		params = new SignatureParameters();
		params.bLevel().setSigningDate(calendar.getTime());
		String deterministicId2 = params.getDeterministicId();

		calendar.add(Calendar.MILLISECOND, 1);

		params = new SignatureParameters();
		params.setSigningCertificate(signingCert);
		params.bLevel().setSigningDate(calendar.getTime());
		String deterministicId3 = params.getDeterministicId();

		assertNotEquals(deterministicId1, deterministicId2);
		assertNotEquals(deterministicId1, deterministicId3);
	}

	@SuppressWarnings("serial")
	private class SignatureParameters extends AbstractSignatureParameters<TimestampParameters> {

	}

}
