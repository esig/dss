package eu.europa.esig.dss.validation.executor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSignature;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationProcessLongTermData;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.policy.jaxb.TimestampConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;

public class DSS1861Test extends AbstractTestValidationExecutor {
	
	private static I18nProvider i18nProvider = I18nProvider.getInstance();
	
	private EtsiValidationPolicy etsiValidationPolicy;
	
	@BeforeEach
	public void init() throws Exception {
		File validationPolicyFile = new File("src/test/resources/policy/default-only-constraint-policy.xml");
		ConstraintsParameters constraintsParameters = getConstraintsParameters(validationPolicyFile);
		
		TimestampConstraints timestamp = constraintsParameters.getTimestamp();
		LevelConstraint failLevelConstraint = new LevelConstraint();
		failLevelConstraint.setLevel(Level.FAIL);
		timestamp.setCoherence(failLevelConstraint);
		
		etsiValidationPolicy = new EtsiValidationPolicy(constraintsParameters);
	}
	
	@Test
	public void test() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1861/pades-timestamp-order-check.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(etsiValidationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlSignature signatureValidation = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureValidation);
		
		XmlValidationProcessLongTermData validationProcessLongTermData = signatureValidation.getValidationProcessLongTermData();
		List<XmlConstraint> constraints = validationProcessLongTermData.getConstraint();
		assertTrue(Utils.isCollectionNotEmpty(constraints));
		
		boolean timestampCoherenceOrderCheckFound = false;
		for (XmlConstraint constraint : constraints) {
			if (i18nProvider.getMessage("TSV_ASTPTCT").getKey().equals(constraint.getName().getNameId())) {
				timestampCoherenceOrderCheckFound = XmlStatus.OK.equals(constraint.getStatus());
			}
		}
		assertTrue(timestampCoherenceOrderCheckFound);
	}
	
	@Test
	public void wrongTimestampOrderTest() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/DSS-1861/pades-wrong-timestamp-order.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(etsiValidationPolicy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.TIMESTAMP_ORDER_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
		DetailedReport detailedReport = reports.getDetailedReport();
		XmlSignature signatureValidation = detailedReport.getXmlSignatureById(detailedReport.getFirstSignatureId());
		assertNotNull(signatureValidation);
		
		XmlValidationProcessLongTermData validationProcessLongTermData = signatureValidation.getValidationProcessLongTermData();
		List<XmlConstraint> constraints = validationProcessLongTermData.getConstraint();
		assertTrue(Utils.isCollectionNotEmpty(constraints));
		
		boolean timestampCoherenceOrderCheckFound = false;
		for (XmlConstraint constraint : constraints) {
			if (i18nProvider.getMessage("TSV_ASTPTCT").getKey().equals(constraint.getName().getNameId())) {
				timestampCoherenceOrderCheckFound = XmlStatus.NOT_OK.equals(constraint.getStatus());
			}
		}
		assertTrue(timestampCoherenceOrderCheckFound);
	}

}
