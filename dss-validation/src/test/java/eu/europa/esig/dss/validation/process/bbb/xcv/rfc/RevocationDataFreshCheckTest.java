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
package eu.europa.esig.dss.validation.process.bbb.xcv.rfc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.policy.jaxb.TimeUnit;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataFreshCheck;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RevocationDataFreshCheckTest extends AbstractTestCheck {

	@Test
	void revocationDataFreshCheck() throws Exception {
		TimeConstraint tc = new TimeConstraint();
		tc.setUnit(TimeUnit.DAYS);
		tc.setValue(1);
		tc.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		Date now = new Date();
		long nowMil = now.getTime();
		xr.setThisUpdate(new Date(nowMil - 43200000)); // 12 hours ago

		XmlRFC result = new XmlRFC();
		RevocationDataFreshCheck rdec = new RevocationDataFreshCheck(i18nProvider, result, new RevocationWrapper(xr), now, tc);
		rdec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	void failedRevocationDataFreshCheck() throws Exception {
		TimeConstraint tc = new TimeConstraint();
		tc.setUnit(TimeUnit.DAYS);
		tc.setValue(1);
		tc.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		Date now = new Date();
		long nowMil = now.getTime();
		xr.setThisUpdate(new Date(nowMil - 172800000)); // 48 hours ago

		XmlRFC result = new XmlRFC();
		RevocationDataFreshCheck rdec = new RevocationDataFreshCheck(i18nProvider, result, new RevocationWrapper(xr), now, tc);
		rdec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	void failedRevocationWithFreshProductionTimeDataFreshCheck() throws Exception {
		TimeConstraint tc = new TimeConstraint();
		tc.setUnit(TimeUnit.DAYS);
		tc.setValue(1);
		tc.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		Date now = new Date();
		long nowMil = now.getTime();
		xr.setThisUpdate(new Date(nowMil - 172800000)); // 48 hours ago
		xr.setProductionDate(new Date(nowMil - 43200000)); // 12 hours ago

		XmlRFC result = new XmlRFC();
		RevocationDataFreshCheck rdec = new RevocationDataFreshCheck(i18nProvider, result, new RevocationWrapper(xr), now, tc);
		rdec.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
