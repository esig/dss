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
package eu.europa.esig.dss.x509;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.model.x509.CertificateToken;

public class CertificateTokenTest {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateTokenTest.class);

	@Test
	public void getKeyUsageBits() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/citizen_ca.cer"));
		List<KeyUsageBit> keyUsageBits = certificate.getKeyUsageBits();
		LOG.info("Key usage citizen_ca : " + keyUsageBits);
		assertTrue(keyUsageBits.contains(KeyUsageBit.CRL_SIGN));

		certificate = DSSUtils.loadCertificate(new File("src/test/resources/TSP_Certificate_2014.crt"));
		keyUsageBits = certificate.getKeyUsageBits();
		LOG.info("Key usage tsp cert : " + keyUsageBits);
		assertFalse(keyUsageBits.contains(KeyUsageBit.CRL_SIGN));
		
		LOG.info(certificate.getDSSIdAsString());
		
	}

}
