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
package eu.europa.esig.dss.validation.process.bbb.isc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificates;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.isc.checks.DigestValuePresentCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DigestValuePresentCheckTest extends AbstractTestCheck {

	@Test
	void digestValuePresentCheckTest() {
		XmlCertificateRef xmlCertificateRef = new XmlCertificateRef();
		xmlCertificateRef.setOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		
		XmlDigestAlgoAndValue xmlDigestAlgoAndValue = new XmlDigestAlgoAndValue();
		xmlDigestAlgoAndValue.setMatch(true);
		xmlCertificateRef.setDigestAlgoAndValue(xmlDigestAlgoAndValue);
		
		XmlCertificate xmlCertificate = new XmlCertificate();
		xmlCertificate.setId("Id-DSS");
		
		XmlRelatedCertificate xmlRelatedCertificate = new XmlRelatedCertificate();
		xmlRelatedCertificate.setCertificate(xmlCertificate);
		xmlRelatedCertificate.getCertificateRefs().add(xmlCertificateRef);
		
		XmlFoundCertificates xmlFoundCertificates = new XmlFoundCertificates();
		xmlFoundCertificates.getRelatedCertificates().add(xmlRelatedCertificate);
		
		XmlSignature xmlSignature = new XmlSignature();
		xmlSignature.setFoundCertificates(xmlFoundCertificates);
		
		XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
		xmlSigningCertificate.setCertificate(xmlCertificate);
		xmlSignature.setSigningCertificate(xmlSigningCertificate);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlISC result = new XmlISC();
		DigestValuePresentCheck dvpc = new DigestValuePresentCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
		dvpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	void digestValueNotPresentCheckTest() {
		XmlCertificateRef xmlCertificateRef = new XmlCertificateRef();
		xmlCertificateRef.setOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
		
		XmlCertificate xmlCertificate = new XmlCertificate();
		xmlCertificate.setId("Id-DSS");
		
		XmlRelatedCertificate xmlRelatedCertificate = new XmlRelatedCertificate();
		xmlRelatedCertificate.setCertificate(xmlCertificate);
		xmlRelatedCertificate.getCertificateRefs().add(xmlCertificateRef);
		
		XmlFoundCertificates xmlFoundCertificates = new XmlFoundCertificates();
		xmlFoundCertificates.getRelatedCertificates().add(xmlRelatedCertificate);
		
		XmlSignature xmlSignature = new XmlSignature();
		xmlSignature.setFoundCertificates(xmlFoundCertificates);
		
		XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
		xmlSigningCertificate.setCertificate(xmlCertificate);
		xmlSignature.setSigningCertificate(xmlSigningCertificate);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlISC result = new XmlISC();
		DigestValuePresentCheck dvpc = new DigestValuePresentCheck(i18nProvider, result, new SignatureWrapper(xmlSignature), new LevelConstraintWrapper(constraint));
		dvpc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}
}
