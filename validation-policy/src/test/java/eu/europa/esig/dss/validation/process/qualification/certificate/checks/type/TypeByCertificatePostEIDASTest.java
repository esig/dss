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

import java.util.ArrayList;
import java.util.List;

import eu.europa.esig.dss.enumerations.QCType;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.enumerations.OidDescription;
import eu.europa.esig.dss.enumerations.QCStatement;
import eu.europa.esig.dss.enumerations.CertificateType;

public class TypeByCertificatePostEIDASTest {

	@Test
	public void esig() {
		CertificateWrapper cert = getCertificate(QCType.QCT_ESIGN);
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(CertificateType.ESIGN, strategy.getType());
	}

	@Test
	public void esigDefault() {
		CertificateWrapper cert = getCertificate();
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(CertificateType.ESIGN, strategy.getType());
	}

	@Test
	public void eseal() {
		CertificateWrapper cert = getCertificate(QCType.QCT_ESEAL);
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(CertificateType.ESEAL, strategy.getType());
	}

	@Test
	public void wsa() {
		CertificateWrapper cert = getCertificate(QCType.QCT_WEB);
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(CertificateType.WSA, strategy.getType());
	}

	// MUST be overruled
	@Test
	public void multiple() {
		CertificateWrapper cert = getCertificate(QCType.QCT_ESIGN, QCType.QCT_ESEAL);
		TypeByCertificatePostEIDAS strategy = new TypeByCertificatePostEIDAS(cert);

		assertEquals(CertificateType.UNKNOWN, strategy.getType());
	}
	
	private CertificateWrapper getCertificate(OidDescription... qcTypesOids) {
		XmlCertificate xmlCertificate = new XmlCertificate();
		List<XmlOID> oids = new ArrayList<>();
		for (OidDescription qcTypeOid : qcTypesOids) {
			XmlOID xmlOID = new XmlOID();
			xmlOID.setValue(qcTypeOid.getOid());
			xmlOID.setDescription(qcTypeOid.getDescription());
			oids.add(xmlOID);
		}
		xmlCertificate.setQCTypes(oids);
		return new CertificateWrapper(xmlCertificate);
	}

}
