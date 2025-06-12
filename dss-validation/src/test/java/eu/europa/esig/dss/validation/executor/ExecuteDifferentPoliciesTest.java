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
package eu.europa.esig.dss.validation.executor;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.CryptographicSuiteFactory;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.ServiceLoader;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class ExecuteDifferentPoliciesTest {

	static Stream<Arguments> data() throws Exception {
		File folderPolicy = new File("src/test/resources/diag-data/policy");
		File folderDiagnosticData = new File("src/test/resources/diag-data");
		Collection<Arguments> dataToRun = new ArrayList<>();

		List<ValidationPolicy> validationPolicies = new ArrayList<>();
		List<CryptographicSuite> cryptographicSuites = new ArrayList<>();

		validationPolicies.add(ValidationPolicyLoader.fromDefaultValidationPolicy().create());
		for (File policyFile : folderPolicy.listFiles()) {
			if (policyFile.isFile()) {
				ValidationPolicy validationPolicy = ValidationPolicyLoader.fromValidationPolicy(policyFile).create();
				validationPolicies.add(validationPolicy);
			}
		}

		ServiceLoader<CryptographicSuiteFactory> loader = ServiceLoader.load(CryptographicSuiteFactory.class);
        for (CryptographicSuiteFactory factory : loader) {
            CryptographicSuite cryptographicSuite = factory.loadDefaultCryptographicSuite();
            cryptographicSuites.add(cryptographicSuite);
        }

		for (File diagData : folderDiagnosticData.listFiles()) {
			if (diagData.isFile()) {
				XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(diagData);
				for (ValidationPolicy validationPolicy : validationPolicies) {
					dataToRun.add(Arguments.of(diagnosticData, ValidationPolicyLoader.fromValidationPolicy(validationPolicy).create()));
					for (CryptographicSuite cryptographicSuite : cryptographicSuites) {
						dataToRun.add(Arguments.of(diagnosticData, ValidationPolicyLoader.fromValidationPolicy(validationPolicy)
								.withCryptographicSuite(cryptographicSuite).create()));
					}
				}
			}
		}
		return dataToRun.stream();
	}

	@ParameterizedTest(name = "Execution {index} : {0} + {1}")
	@MethodSource("data")
	void noError(XmlDiagnosticData diagnosticData, ValidationPolicy policy) {
		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(policy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticDataJaxb());
		assertNotNull(reports.getSimpleReportJaxb());
		assertNotNull(reports.getDetailedReportJaxb());
		assertNotNull(reports.getEtsiValidationReportJaxb());
	}

}
