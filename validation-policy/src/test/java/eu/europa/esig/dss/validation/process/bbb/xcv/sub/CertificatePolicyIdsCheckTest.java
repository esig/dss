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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.MultiValuesConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificatePolicyIdsCheck;

public class CertificatePolicyIdsCheckTest extends AbstractTestCheck {

	@Test
	public void certificatePolicyIdsCheck() throws Exception {
		List<XmlCertificatePolicy> policyIds = new ArrayList<XmlCertificatePolicy>();
		XmlCertificatePolicy oid = new XmlCertificatePolicy();
		oid.setValue("1.3.76.38.1.1.1");
		policyIds.add(oid);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("1.3.76.38.1.1.1");

		XmlCertificate xc = new XmlCertificate();
		xc.setCertificatePolicies(policyIds);

		XmlSubXCV result = new XmlSubXCV();
		CertificatePolicyIdsCheck cpic = new CertificatePolicyIdsCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
		cpic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedCertificatePolicyIdsCheck() throws Exception {
		List<XmlCertificatePolicy> policyIds = new ArrayList<XmlCertificatePolicy>();
		XmlCertificatePolicy oid = new XmlCertificatePolicy();
		oid.setValue("1.3.76.38.1.1.1");
		policyIds.add(oid);

		MultiValuesConstraint constraint = new MultiValuesConstraint();
		constraint.setLevel(Level.FAIL);
		constraint.getId().add("1.3.76.38.1.1.2");

		XmlCertificate xc = new XmlCertificate();
		xc.setCertificatePolicies(policyIds);

		XmlSubXCV result = new XmlSubXCV();
		CertificatePolicyIdsCheck cpic = new CertificatePolicyIdsCheck(i18nProvider, result, new CertificateWrapper(xc), constraint);
		cpic.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
