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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;

import java.util.Calendar;

import static org.junit.jupiter.api.Assertions.assertNotEquals;

class DeterministicIdGenerationTest extends PKIFactoryAccess {

	private CertificateToken signingCert;

	public DeterministicIdGenerationTest() {
	}

	@BeforeEach
	void setUp() throws Exception {
		signingCert = getSigningCert();
	}

	@RepeatedTest(10)
	void testDifferentDeterministicId() throws InterruptedException {

		Calendar calendar = Calendar.getInstance();

		XAdESSignatureParameters params = new XAdESSignatureParameters();
		params.setSigningCertificate(signingCert);
		params.bLevel().setSigningDate(calendar.getTime());
		String deterministicId1 = params.getContext().getDeterministicId();

		params = new XAdESSignatureParameters();
		params.bLevel().setSigningDate(calendar.getTime());
		String deterministicId2 = params.getDeterministicId();

		calendar.add(Calendar.MILLISECOND, 1);

		params = new XAdESSignatureParameters();
		params.setSigningCertificate(signingCert);
		params.bLevel().setSigningDate(calendar.getTime());
		String deterministicId3 = params.getDeterministicId();

		assertNotEquals(deterministicId1, deterministicId2);
		assertNotEquals(deterministicId1, deterministicId3);
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}

}
