package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.validation.reports.Reports;

@RunWith(Parameterized.class)
public class ExecuteDifferentPoliciesTest {

	@Parameters(name = "Execution {index} : {0} + {1}")
	public static Collection<Object[]> data() throws Exception {
		File folderPolicy = new File("src/test/resources/policy");
		File[] policyFiles = folderPolicy.listFiles();
		File folderDiagnosticData = new File("src/test/resources");
		File[] diagDataFiles = folderDiagnosticData.listFiles();
		Collection<Object[]> dataToRun = new ArrayList<Object[]>();
		for (File diagData : diagDataFiles) {
			if (diagData.isFile()) {
				XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(diagData);
				for (File policyFile : policyFiles) {
					if (policyFile.isFile()) {
						ConstraintsParameters validationPolicy = ValidationPolicyFacade.newFacade().unmarshall(policyFile);
						dataToRun.add(new Object[] { diagnosticData, new EtsiValidationPolicy(validationPolicy) });
					}
				}

				dataToRun.add(new Object[] { diagnosticData, ValidationPolicyFacade.newFacade().getDefaultValidationPolicy() });
				dataToRun.add(new Object[] { diagnosticData, ValidationPolicyFacade.newFacade().getTrustedListValidationPolicy() });

			}
		}
		return dataToRun;
	}

	private final XmlDiagnosticData diagnoticData;
	private final ValidationPolicy policy;

	public ExecuteDifferentPoliciesTest(XmlDiagnosticData diagnoticData, ValidationPolicy policy) {
		this.diagnoticData = diagnoticData;
		this.policy = policy;
	}

	@Test
	public void noError() throws Exception {
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
