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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.policy.LevelConstraintWrapper;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateValidityRangeCheck;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CertificateValidityRangeCheckTest extends AbstractTestCheck {

	@Test
	void certificateExpirationCheck() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		Date now = new Date();
		long nowMil = now.getTime();
		XmlCertificate xc = new XmlCertificate();
		xc.setNotAfter(new Date(nowMil + 86400000)); // in 24 hours
		xc.setNotBefore(new Date(nowMil - 86400000)); // 24 hours ago

		XmlSubXCV result = new XmlSubXCV();
		CertificateValidityRangeCheck<XmlSubXCV> cec = new CertificateValidityRangeCheck<>(i18nProvider, result, new CertificateWrapper(xc),
				null, true, true, true, new Date(), new LevelConstraintWrapper(constraint));
		cec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	void failedCertificateExpirationCheck() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		Date now = new Date();
		long nowMil = now.getTime();
		XmlCertificate xc = new XmlCertificate();
		xc.setNotAfter(new Date(nowMil - 86400000)); // 24 hours ago
		xc.setNotBefore(new Date(nowMil - 172800000)); // 48 hours ago

		XmlSubXCV result = new XmlSubXCV();
		CertificateValidityRangeCheck<XmlSubXCV> cec = new CertificateValidityRangeCheck<>(i18nProvider, result, new CertificateWrapper(xc),
				null, true, true, true, new Date(), new LevelConstraintWrapper(constraint));
		cec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
