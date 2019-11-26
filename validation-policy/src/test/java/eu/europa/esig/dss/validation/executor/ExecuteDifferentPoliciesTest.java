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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.validation.reports.Reports;


public class ExecuteDifferentPoliciesTest {

	public static Stream<Arguments> data() throws Exception {
		File folderPolicy = new File("src/test/resources/policy");
		File[] policyFiles = folderPolicy.listFiles();
		File folderDiagnosticData = new File("src/test/resources");
		File[] diagDataFiles = folderDiagnosticData.listFiles();
		Collection<Arguments> dataToRun = new ArrayList<Arguments>();
		for (File diagData : diagDataFiles) {
			if (diagData.isFile()) {
				XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(diagData);
				for (File policyFile : policyFiles) {
					if (policyFile.isFile()) {
						ConstraintsParameters validationPolicy = ValidationPolicyFacade.newFacade().unmarshall(policyFile);
						dataToRun.add(Arguments.of( diagnosticData, new EtsiValidationPolicy(validationPolicy) ));
					}
				}

				dataToRun.add(Arguments.of(diagnosticData, ValidationPolicyFacade.newFacade().getDefaultValidationPolicy() ));
				dataToRun.add(Arguments.of(diagnosticData, ValidationPolicyFacade.newFacade().getTrustedListValidationPolicy() ));

			}
		}
		return dataToRun.stream();
	}

	@ParameterizedTest(name = "Execution {index} : {0} + {1}")
	@MethodSource("data")
	public void noError(XmlDiagnosticData diagnoticData, ValidationPolicy policy) throws Exception {
		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnoticData);
		executor.setValidationPolicy(policy);
		executor.setCurrentTime(diagnoticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticDataJaxb());
		assertNotNull(reports.getSimpleReportJaxb());
		assertNotNull(reports.getDetailedReportJaxb());
		assertNotNull(reports.getEtsiValidationReportJaxb());
	}

}
