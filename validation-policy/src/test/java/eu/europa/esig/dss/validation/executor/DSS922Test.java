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
package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.io.InputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class DSS922Test {

	@Test
	public void signedDataNotFound() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/DSS-922/diag-data.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class);
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	private EtsiValidationPolicy loadPolicy() throws Exception {
		FileInputStream policyFis = new FileInputStream("src/test/resources/DSS-922/policy.xml");
		ConstraintsParameters policyJaxB = getJAXBObjectFromString(policyFis, ConstraintsParameters.class);
		assertNotNull(policyJaxB);
		return new EtsiValidationPolicy(policyJaxB);
	}

	@SuppressWarnings("unchecked")
	private <T extends Object> T getJAXBObjectFromString(InputStream is, Class<T> clazz) throws Exception {
		JAXBContext context = JAXBContext.newInstance(clazz.getPackage().getName());
		Unmarshaller unmarshaller = context.createUnmarshaller();
		return (T) unmarshaller.unmarshal(is);
	}
}
