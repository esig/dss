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
package eu.europa.esig.dss.validation.process.qualification.certificate.checks.type;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.QCStatement;
import eu.europa.esig.dss.validation.process.qualification.certificate.Type;

public class TypeByCertificatePostEIDASTest {

	@Test
	public void esig() {

		CertificateWrapper cert = new MockCertificateWrapper(Arrays.asList(QCStatement.QCT_ESIGN.getOid()));
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(Type.ESIGN, strategy.getType());
	}

	@Test
	public void esigDefault() {

		CertificateWrapper cert = new MockCertificateWrapper(Collections.<String>emptyList());
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(Type.ESIGN, strategy.getType());
	}

	@Test
	public void eseal() {

		CertificateWrapper cert = new MockCertificateWrapper(Arrays.asList(QCStatement.QCT_ESEAL.getOid()));
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(Type.ESEAL, strategy.getType());
	}

	@Test
	public void wsa() {
		CertificateWrapper cert = new MockCertificateWrapper(Arrays.asList(QCStatement.QCT_WEB.getOid()));
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(Type.WSA, strategy.getType());
	}

	// MUST be overruled
	@Test
	public void multiple() {
		CertificateWrapper cert = new MockCertificateWrapper(
				Arrays.asList(QCStatement.QCT_ESIGN.getOid(), QCStatement.QCT_ESEAL.getOid()));
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(Type.UNKNOWN, strategy.getType());
	}

	private class MockCertificateWrapper extends CertificateWrapper {

		private final List<String> qcTypesOids;

		public MockCertificateWrapper(List<String> qcTypesOids) {
			super(null);
			this.qcTypesOids = qcTypesOids;
		}

		@Override
		public List<String> getQCTypes() {
			return qcTypesOids;
		}

	}

}
