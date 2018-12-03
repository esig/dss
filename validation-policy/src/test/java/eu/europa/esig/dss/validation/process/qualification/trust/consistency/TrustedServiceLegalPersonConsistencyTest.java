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
package eu.europa.esig.dss.validation.process.qualification.trust.consistency;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.process.qualification.trust.consistency.TrustedServiceCondition;
import eu.europa.esig.dss.validation.process.qualification.trust.consistency.TrustedServiceLegalPersonConsistency;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class TrustedServiceLegalPersonConsistencyTest {

	private TrustedServiceCondition condition = new TrustedServiceLegalPersonConsistency();

	@Test
	public void testEmpty() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testLegalOnly() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_FOR_LEGAL_PERSON));
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testESigOnly() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_FOR_ESIG));
		assertTrue(condition.isConsistent(service));
	}

	@Test
	public void testConflict() {
		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_FOR_ESIG, ServiceQualification.QC_FOR_LEGAL_PERSON));
		assertFalse(condition.isConsistent(service));
	}

}
