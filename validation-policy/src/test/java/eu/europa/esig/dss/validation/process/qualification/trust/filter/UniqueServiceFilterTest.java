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
package eu.europa.esig.dss.validation.process.qualification.trust.filter;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.trust.ServiceQualification;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class UniqueServiceFilterTest {

	private final static Date AFTER_EIDAS_DATE = DatatypeConverter.parseDateTime("2017-07-01T00:00:00-00:00").getTime();

	@Test
	public void testCanConcludeOneTrustService() {

		CertificateWrapper emptyCert = new MockCertificateWrapper(AFTER_EIDAS_DATE, Collections.<String> emptyList(), Collections.<String> emptyList(),
				Collections.<String> emptyList());

		UniqueServiceFilter filter = new UniqueServiceFilter(emptyCert);
		List<TrustedServiceWrapper> trustServices = new ArrayList<TrustedServiceWrapper>();

		TrustedServiceWrapper ts0 = new TrustedServiceWrapper();
		ts0.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_STATEMENT, ServiceQualification.QC_WITH_QSCD, ServiceQualification.QC_FOR_ESIG));
		trustServices.add(ts0);

		List<TrustedServiceWrapper> filtered = filter.filter(trustServices);
		assertTrue(Utils.isCollectionNotEmpty(filtered));
	}

	@Test
	public void testCanConclude() {

		CertificateWrapper emptyCert = new MockCertificateWrapper(AFTER_EIDAS_DATE, Collections.<String> emptyList(), Collections.<String> emptyList(),
				Collections.<String> emptyList());

		UniqueServiceFilter filter = new UniqueServiceFilter(emptyCert);
		List<TrustedServiceWrapper> trustServices = new ArrayList<TrustedServiceWrapper>();

		TrustedServiceWrapper ts0 = new TrustedServiceWrapper();
		ts0.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_STATEMENT, ServiceQualification.QC_WITH_QSCD, ServiceQualification.QC_FOR_ESIG));
		trustServices.add(ts0);

		TrustedServiceWrapper ts1 = new TrustedServiceWrapper();
		ts1.setCapturedQualifiers(
				Arrays.asList(ServiceQualification.QC_STATEMENT, ServiceQualification.QC_QSCD_MANAGED_ON_BEHALF, ServiceQualification.QC_FOR_ESIG));
		trustServices.add(ts1);

		List<TrustedServiceWrapper> filtered = filter.filter(trustServices);
		assertTrue(Utils.isCollectionNotEmpty(filtered));
	}

	@Test
	public void testCannotConclude() {

		CertificateWrapper emptyCert = new MockCertificateWrapper(AFTER_EIDAS_DATE, Collections.<String> emptyList(), Collections.<String> emptyList(),
				Collections.<String> emptyList());

		UniqueServiceFilter filter = new UniqueServiceFilter(emptyCert);
		List<TrustedServiceWrapper> trustServices = new ArrayList<TrustedServiceWrapper>();

		TrustedServiceWrapper ts0 = new TrustedServiceWrapper();
		ts0.setCapturedQualifiers(Arrays.asList(ServiceQualification.QC_STATEMENT, ServiceQualification.QC_WITH_QSCD, ServiceQualification.QC_FOR_ESIG));
		trustServices.add(ts0);

		TrustedServiceWrapper ts1 = new TrustedServiceWrapper();
		ts1.setCapturedQualifiers(
				Arrays.asList(ServiceQualification.QC_STATEMENT, ServiceQualification.QC_QSCD_MANAGED_ON_BEHALF, ServiceQualification.QC_FOR_ESEAL));
		trustServices.add(ts1);

		List<TrustedServiceWrapper> filtered = filter.filter(trustServices);
		assertTrue(Utils.isCollectionEmpty(filtered));
	}

	private class MockCertificateWrapper extends CertificateWrapper {

		private final Date notBefore;
		private final List<String> policyOids;
		private final List<String> qcStatementOids;
		private final List<String> qcTypesOids;

		public MockCertificateWrapper(Date notBefore, List<String> policyOids, List<String> qcStatementOids, List<String> qcTypesOids) {
			super(null);
			this.notBefore = notBefore;
			this.policyOids = policyOids;
			this.qcStatementOids = qcStatementOids;
			this.qcTypesOids = qcTypesOids;
		}

		@Override
		public Date getNotBefore() {
			return notBefore;
		}

		@Override
		public List<String> getPolicyIds() {
			return policyOids;
		}

		@Override
		public List<String> getQCStatementIds() {
			return qcStatementOids;
		}

		@Override
		public List<String> getQCTypes() {
			return qcTypesOids;
		}

	}

}
