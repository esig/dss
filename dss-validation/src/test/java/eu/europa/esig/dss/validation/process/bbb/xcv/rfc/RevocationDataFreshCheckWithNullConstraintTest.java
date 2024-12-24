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
package eu.europa.esig.dss.validation.process.bbb.xcv.rfc;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlRFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.bbb.AbstractTestCheck;
import eu.europa.esig.dss.validation.process.bbb.xcv.rfc.checks.RevocationDataFreshCheckWithNullConstraint;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RevocationDataFreshCheckWithNullConstraintTest extends AbstractTestCheck {

	@Test
	void revocationDataCheckWithNullConstraint() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		Date now = new Date();
		long nowMil = now.getTime();
		xr.setThisUpdate(new Date(nowMil - 67800000)); // 18 hours ago
		xr.setNextUpdate(new Date(nowMil + 43200000)); // 12 hours after
		// freshness is 24 hours
		xr.setProductionDate(new Date(nowMil - 67800000)); // 18 hours ago ->
		// fresh

		XmlRFC result = new XmlRFC();
		RevocationDataFreshCheckWithNullConstraint rdfwncc = new RevocationDataFreshCheckWithNullConstraint(i18nProvider, result,
				new RevocationWrapper(xr), now, constraint);
		rdfwncc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.OK, constraints.get(0).getStatus());
	}

	@Test
	void revocationDataProductionTimeAfterControlTimeCheckWithNullConstraint() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		Date now = new Date();
		long nowMil = now.getTime();
		xr.setThisUpdate(new Date(nowMil - 129600000)); // 36 hours ago
		xr.setNextUpdate(new Date(nowMil - 43200000)); // 12 hours ago -> max
														// freshness is 24 hours
		xr.setProductionDate(new Date(nowMil - 72000000)); // 20 hours ago ->
															// fresh

		XmlRFC result = new XmlRFC();
		RevocationDataFreshCheckWithNullConstraint rdfwncc = new RevocationDataFreshCheckWithNullConstraint(i18nProvider, result,
				new RevocationWrapper(xr), now, constraint);
		rdfwncc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

	@Test
	void failedRevocationDataFreshCheckWithNullConstraint() {
		LevelConstraint constraint = new LevelConstraint();
		constraint.setLevel(Level.FAIL);

		XmlRevocation xr = new XmlRevocation();
		Date now = new Date();
		long nowMil = now.getTime();
		xr.setThisUpdate(new Date(nowMil - 129600000)); // 36 hours ago
		xr.setNextUpdate(new Date(nowMil - 43200000)); // 12 hours ago -> max
														// freshness is 24 hours
		xr.setProductionDate(new Date(nowMil - 144000000)); // 20 hours ago ->
															// not fresh

		XmlRFC result = new XmlRFC();
		RevocationDataFreshCheckWithNullConstraint rdfwncc = new RevocationDataFreshCheckWithNullConstraint(i18nProvider, result,
				new RevocationWrapper(xr), now, constraint);
		rdfwncc.execute();

		List<XmlConstraint> constraints = result.getConstraint();
		assertEquals(1, constraints.size());
		assertEquals(XmlStatus.NOT_OK, constraints.get(0).getStatus());
	}

}
