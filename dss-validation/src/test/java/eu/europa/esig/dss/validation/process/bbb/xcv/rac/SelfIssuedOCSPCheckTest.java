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
package eu.europa.esig.dss.validation.process.bbb.xcv.rac;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRAC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rac.checks.SelfIssuedOCSPCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SelfIssuedOCSPCheckTest extends AbstractTestCheck {

	private static final String CERT_ID = "C-1";

	@Test
	void revocationCertHashPresenceCheck() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCertificate xmlCertificate = new XmlCertificate();
		xmlCertificate.setId(CERT_ID);

		XmlRevocation xmlRevocation = new XmlRevocation();
		XmlCertificate ocspResponderCertificate = new XmlCertificate();
		ocspResponderCertificate.setId("");

		XmlChainItem xmlChainItem = new XmlChainItem();
		xmlChainItem.setCertificate(ocspResponderCertificate);
		xmlRevocation.getCertificateChain().add(xmlChainItem);

		XmlRAC result = new XmlRAC();
		SelfIssuedOCSPCheck sioc = new SelfIssuedOCSPCheck(i18nProvider, result, new CertificateWrapper(xmlCertificate),
				new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
		sioc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	void failRevocationCertHashPresenceCheck() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCertificate xmlCertificate = new XmlCertificate();
		xmlCertificate.setId(CERT_ID);

		XmlRevocation xmlRevocation = new XmlRevocation();
		XmlCertificate ocspResponderCertificate = new XmlCertificate();
		ocspResponderCertificate.setId(CERT_ID);

		XmlChainItem xmlChainItem = new XmlChainItem();
		xmlChainItem.setCertificate(ocspResponderCertificate);
		xmlRevocation.getCertificateChain().add(xmlChainItem);

		XmlRAC result = new XmlRAC();
		SelfIssuedOCSPCheck sioc = new SelfIssuedOCSPCheck(i18nProvider, result, new CertificateWrapper(xmlCertificate),
				new RevocationWrapper(xmlRevocation), new LevelConstraintWrapper(constraint));
		sioc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
