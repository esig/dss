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
package eu.europa.esig.dss.test.mock;

import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import eu.europa.esig.dss.tsl.Condition;
import eu.europa.esig.dss.tsl.ServiceInfo;
import eu.europa.esig.dss.tsl.ServiceInfoStatus;
import eu.europa.esig.dss.util.MutableTimeDependentValues;

public class MockServiceInfo extends ServiceInfo {

	public static final String CA_QC = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
	public static final String SERVICE_STATUS_UNDERSUPERVISION_119612 = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision";

	public MockServiceInfo() {

		setTspName("DSS, Mock Office DSS-CA");
		setServiceName("DSS, Mock Service Name");
		Calendar calendar = Calendar.getInstance();
		calendar.add(Calendar.YEAR, -15);

		MutableTimeDependentValues<ServiceInfoStatus> statusList = new MutableTimeDependentValues<ServiceInfoStatus>();
		Map<String, List<Condition>> emptyMap = new HashMap<String, List<Condition>>();
		List<String> emptyList = Collections.emptyList();
		statusList.addOldest(new ServiceInfoStatus(CA_QC, SERVICE_STATUS_UNDERSUPERVISION_119612, emptyMap, emptyList, null, calendar.getTime(), null));
		setStatus(statusList);
	}
}
