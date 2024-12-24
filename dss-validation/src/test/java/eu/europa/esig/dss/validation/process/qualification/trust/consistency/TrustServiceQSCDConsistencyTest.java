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
package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.ServiceQualification;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustServiceQSCDConsistencyTest extends AbstractTrustServiceConsistencyTest {

	private TrustServiceCondition condition = new TrustServiceQSCDConsistency();

	@Test
	void testNoInfo() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		assertTrue(condition.isConsistent(service));
	}

	@Test
	void testQSCD() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_WITH_QSCD.getUri()));
		assertTrue(condition.isConsistent(service));
	}

	@Test
	void testNoQSCD() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_QSCD.getUri()));
		assertTrue(condition.isConsistent(service));
	}

	@Test
	void testConflict() {
		TrustServiceWrapper service = new TrustServiceWrapper();
		service.setCapturedQualifiers(getXmlQualifierList(ServiceQualification.QC_NO_QSCD.getUri(), ServiceQualification.QC_WITH_QSCD.getUri()));
		assertFalse(condition.isConsistent(service));
	}

}
