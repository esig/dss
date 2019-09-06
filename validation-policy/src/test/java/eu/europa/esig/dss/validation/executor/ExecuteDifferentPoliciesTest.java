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
