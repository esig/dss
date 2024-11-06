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
package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerRole;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.sav.checks.CertifiedRolesCheck;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CertifiedRolesCheckTest extends AbstractTestCheck {

	@Test
	void certifiedRolesCheck() {
		XmlSignerRole xmlSignerRole = new XmlSignerRole();
		xmlSignerRole.setRole("Valid_Role");
		xmlSignerRole.setCategory(EndorsementType.CERTIFIED);

		XmlSignature sig = new XmlSignature();
		sig.getSignerRole().add(xmlSignerRole);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("Valid_Role");

		XmlSAV result = new XmlSAV();
		CertifiedRolesCheck crc = new CertifiedRolesCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
		crc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	void notCertifiedRolesCheck() {
		XmlSignerRole xmlSignerRole = new XmlSignerRole();
		xmlSignerRole.setRole("Invalid_Role");
		xmlSignerRole.setCategory(EndorsementType.CERTIFIED);

		XmlSignature sig = new XmlSignature();
		sig.getSignerRole().add(xmlSignerRole);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("Valid_Role");

		XmlSAV result = new XmlSAV();
		CertifiedRolesCheck crc = new CertifiedRolesCheck(i18nProvider, result, new SignatureWrapper(sig), constraint);
		crc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
