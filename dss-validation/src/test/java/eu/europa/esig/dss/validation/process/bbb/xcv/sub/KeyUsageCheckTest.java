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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlKeyUsages;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.KeyUsageCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class KeyUsageCheckTest extends AbstractTestCheck {

	@Test
	public void keyUsageCheck() {
		XmlKeyUsages keyUsages = new XmlKeyUsages();
		keyUsages.setOID(CertificateExtensionEnum.KEY_USAGE.getOid());
		keyUsages.getKeyUsageBit().add(KeyUsageBit.CRL_SIGN);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add(keyUsages.getKeyUsageBit().get(0).getValue());

		XmlCertificate xc = new XmlCertificate();
		xc.getCertificateExtensions().add(keyUsages);

		XmlSubXCV result = new XmlSubXCV();
		KeyUsageCheck kuc = new KeyUsageCheck(i18nProvider, result, new CertificateWrapper(xc), Context.REVOCATION, SubContext.SIGNING_CERT, constraint);
		kuc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedKeyUsageCheck() {
		XmlKeyUsages keyUsages = new XmlKeyUsages();
		keyUsages.setOID(CertificateExtensionEnum.KEY_USAGE.getOid());
		keyUsages.getKeyUsageBit().add(KeyUsageBit.CRL_SIGN);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("Invalid_Key");

		XmlCertificate xc = new XmlCertificate();
		xc.getCertificateExtensions().add(keyUsages);

		XmlSubXCV result = new XmlSubXCV();
		KeyUsageCheck kuc = new KeyUsageCheck(i18nProvider, result, new CertificateWrapper(xc), Context.REVOCATION, SubContext.SIGNING_CERT, constraint);
		kuc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	public void multiValuesCheck() {
		XmlKeyUsages keyUsages = new XmlKeyUsages();
		keyUsages.setOID(CertificateExtensionEnum.KEY_USAGE.getOid());
		keyUsages.getKeyUsageBit().add(KeyUsageBit.DIGITAL_SIGNATURE);
		keyUsages.getKeyUsageBit().add(KeyUsageBit.NON_REPUDIATION);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add(KeyUsageBit.NON_REPUDIATION.getValue());

		XmlCertificate xc = new XmlCertificate();
		xc.getCertificateExtensions().add(keyUsages);
		constraint.getId().add(keyUsages.getKeyUsageBit().get(0).getValue());

		XmlSubXCV result = new XmlSubXCV();
		KeyUsageCheck kuc = new KeyUsageCheck(i18nProvider, result, new CertificateWrapper(xc), Context.SIGNATURE, SubContext.SIGNING_CERT, constraint);
		kuc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

}
