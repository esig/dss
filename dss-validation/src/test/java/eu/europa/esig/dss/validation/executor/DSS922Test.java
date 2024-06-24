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

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.SubContext;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class DSS922Test {

	@Test
	public void dss922Test() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/DSS-922-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TRY_LATER, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void testIgnoreRevocationFreshness() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/DSS-922-diag-data.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		ValidationPolicy policy = loadPolicy();
		policy.getRevocationFreshnessConstraint(Context.SIGNATURE, SubContext.SIGNING_CERT).setLevel(Level.IGNORE);
		executor.setValidationPolicy(policy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	private ValidationPolicy loadPolicy() throws Exception {
		return ValidationPolicyFacade.newFacade().getValidationPolicy(new File("src/test/resources/diag-data/policy/DSS-922-policy.xml"));
	}

}
