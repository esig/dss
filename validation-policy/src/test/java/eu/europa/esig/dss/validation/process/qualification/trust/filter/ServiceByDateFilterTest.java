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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.qualification.trust.filter.ServiceByDateFilter;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;

public class ServiceByDateFilterTest {

	private final static Date DATE1 = DatatypeConverter.parseDateTime("2015-07-01T00:00:00-00:00").getTime();
	private final static Date DATE2 = DatatypeConverter.parseDateTime("2016-07-01T00:00:00-00:00").getTime();
	private final static Date DATE3 = DatatypeConverter.parseDateTime("2017-07-01T00:00:00-00:00").getTime();

	@Test
	public void noCAQC() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE2);
		assertTrue(Utils.isCollectionEmpty(filter.filter(new ArrayList<TrustedServiceWrapper>())));
	}

	@Test
	public void testInRange() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE2);

		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setStartDate(DATE1);
		service.setEndDate(DATE3);

		assertTrue(filter.isAcceptable(service));
	}

	@Test
	public void testNoEndRange() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE2);

		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setStartDate(DATE1);

		assertTrue(filter.isAcceptable(service));
	}

	@Test
	public void testNoDateRange() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE2);

		TrustedServiceWrapper service = new TrustedServiceWrapper();

		assertFalse(filter.isAcceptable(service));
	}

	@Test
	public void testNotInRange() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE3);

		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setStartDate(DATE1);
		service.setEndDate(DATE2);

		assertFalse(filter.isAcceptable(service));
	}

	@Test
	public void testInRangeSameStartDate() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE1);

		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setStartDate(DATE1);
		service.setEndDate(DATE3);

		assertTrue(filter.isAcceptable(service));
	}

	@Test
	public void testInRangeSameEndDate() {
		ServiceByDateFilter filter = new ServiceByDateFilter(DATE3);

		TrustedServiceWrapper service = new TrustedServiceWrapper();
		service.setStartDate(DATE1);
		service.setEndDate(DATE3);

		assertTrue(filter.isAcceptable(service));
	}

}
