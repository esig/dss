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

import java.util.Calendar;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.CertificateNotRevokedCheck;

public class CertificateRevokedCheckTest extends AbstractTestCheck {

	private static final Calendar CAL1 = DatatypeConverter.parseDate("2017-01-01");
	private static final Calendar CAL2 = DatatypeConverter.parseDate("2018-01-01");

	@Test
	public void certificateRevokedCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCertificateRevocation xcr = new XmlCertificateRevocation();
		xcr.setStatus(CertificateStatus.REVOKED);
		xcr.setReason(RevocationReason.CERTIFICATE_HOLD);
		XmlRevocation xr = new XmlRevocation();
		xcr.setRevocation(xr);

		XmlSubXCV result = new XmlSubXCV();
		CertificateNotRevokedCheck cec = new CertificateNotRevokedCheck(i18nProvider, result, new CertificateRevocationWrapper(xcr), CAL2.getTime(),
				constraint, SubContext.CA_CERTIFICATE);
		cec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	public void failedCertificateRevokedCheck() throws Exception {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlCertificateRevocation xcr = new XmlCertificateRevocation();
		xcr.setStatus(CertificateStatus.REVOKED);
		xcr.setRevocationDate(CAL1.getTime());
		xcr.setReason(RevocationReason.CA_COMPROMISE);
		XmlRevocation xr = new XmlRevocation();
		xcr.setRevocation(xr);

		XmlSubXCV result = new XmlSubXCV();
		CertificateNotRevokedCheck cec = new CertificateNotRevokedCheck(i18nProvider, result, new CertificateRevocationWrapper(xcr), CAL2.getTime(),
				constraint, SubContext.CA_CERTIFICATE);
		cec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
