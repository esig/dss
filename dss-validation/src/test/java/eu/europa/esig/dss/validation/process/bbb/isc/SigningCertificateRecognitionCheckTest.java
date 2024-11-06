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
package eu.europa.esig.dss.validation.process.bbb.isc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.isc.checks.SigningCertificateRecognitionCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SigningCertificateRecognitionCheckTest extends AbstractTestCheck {

	@Test
	void signingCertificateRecognitionCheck() {
		XmlSigningCertificate xsc = new XmlSigningCertificate();
		XmlCertificate xCert = new XmlCertificate();
		xCert.setId("C-79513A7C5EFA8B43C0042CAAA132226FFD959EA9AA9B9331A5BF3F6383381DBC");
		xsc.setCertificate(xCert);

		XmlSignature sig = new XmlSignature();
		sig.setSigningCertificate(xsc);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlISC result = new XmlISC();

		SigningCertificateRecognitionCheck scrc = new SigningCertificateRecognitionCheck(i18nProvider, result,
				new SignatureWrapper(sig), constraint);

		scrc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}
	
	@Test
	void signingCertificateNotRecognizedCheck() {
		XmlSignature sig = new XmlSignature();

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlISC result = new XmlISC();

		SigningCertificateRecognitionCheck scrc = new SigningCertificateRecognitionCheck(i18nProvider, result,
				new SignatureWrapper(sig), constraint);

		scrc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}
	
	@Test
	void publicKeyCheck() {
		XmlSignature sig = new XmlSignature();
		
		XmlSigningCertificate xmlSigningCertificate = new XmlSigningCertificate();
		xmlSigningCertificate.setPublicKey("Public Key".getBytes());
		sig.setSigningCertificate(xmlSigningCertificate);

		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlISC result = new XmlISC();

		SigningCertificateRecognitionCheck scrc = new SigningCertificateRecognitionCheck(i18nProvider, result,
				new SignatureWrapper(sig), constraint);

		scrc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
