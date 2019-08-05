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
package eu.europa.esig.dss.validation;

import static org.junit.Assert.assertEquals;

import java.io.File;

import org.junit.Test;

import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;

public class DSSPKUtilsTest {

	@Test
	public void getPublicKeyEncryptionAlgo() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/BA-QC-Wurzel-CA-2_PN.txt"));
		assertEquals(EncryptionAlgorithm.RSA, EncryptionAlgorithm.forKey(certificate.getPublicKey()));
	}

	@Test
	public void getPublicKeyEncryptionAlgoECDSA() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ecdsa.cer"));
		assertEquals(EncryptionAlgorithm.ECDSA, EncryptionAlgorithm.forKey(certificate.getPublicKey()));
	}

	@Test
	public void getPublicKeySize() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/BA-QC-Wurzel-CA-2_PN.txt"));
		assertEquals(2048, DSSPKUtils.getPublicKeySize(certificate.getPublicKey()));
		assertEquals("2048", DSSPKUtils.getPublicKeySize(certificate));
	}

	@Test
	public void getPublicKeySizeECDSA() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/ecdsa.cer"));
		assertEquals(256, DSSPKUtils.getPublicKeySize(certificate.getPublicKey()));
	}

	@Test
	public void getPublicKeySizeSelfSign() {
		CertificateToken certificate = DSSUtils.loadCertificate(new File("src/test/resources/belgiumrca2-self-sign.crt"));
		assertEquals(2048, DSSPKUtils.getPublicKeySize(certificate.getPublicKey()));
		assertEquals("2048", DSSPKUtils.getPublicKeySize(certificate));

	}

}
