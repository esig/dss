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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CertificateTokenTest {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateTokenTest.class);

	@Test
	void getKeyUsageBits() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
		List<KeyUsageBit> keyUsageBits = certificate.getKeyUsageBits();
		LOG.info("Key usage citizen_ca : " + keyUsageBits);
		assertTrue(keyUsageBits.contains(KeyUsageBit.CRL_SIGN));
		assertTrue(certificate.isCA());
		assertEquals(0, certificate.getPathLenConstraint());

		certificate = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
		keyUsageBits = certificate.getKeyUsageBits();
		LOG.info("Key usage tsp cert : " + keyUsageBits);
		assertFalse(keyUsageBits.contains(KeyUsageBit.CRL_SIGN));
		assertFalse(certificate.isCA());
		assertEquals(-1, certificate.getPathLenConstraint());
		
		LOG.info(certificate.getDSSIdAsString());
	}

}
