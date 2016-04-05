package eu.europa.esig.dss.validation.policy.bbb;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.bbb.util.TestDiagnosticDataGenerator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.bbb.vci.ValidationContextInitialization;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.Level;

public class ValidationContextInitializationTest extends AbstractValidationPolicy {

	private static final Logger logger = LoggerFactory.getLogger(ValidationContextInitializationTest.class);

	@Test
	public void testWithBasicData() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ConstraintsParameters parameters = getConstraintsParameters();
		ValidationPolicy policy = new EtsiValidationPolicy(parameters);

		ValidationContextInitialization verification = new ValidationContextInitialization(diagnosticData.getSignatures().get(0), Context.SIGNATURE,
				policy);
		XmlVCI vci = verification.execute();

		for (XmlConstraint constraint : vci.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.PASSED, vci.getConclusion().getIndication());
		Assert.assertEquals(1, vci.getConstraint().size());
	}

	@Test
	public void testWithMandatoryPolicyAndNoPolicyInTheData() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ConstraintsParameters parameters = getConstraintsParameters();
		parameters.getSignatureConstraints().setAcceptablePolicies(createMultiValueConstraint(Level.FAIL));
		parameters.getSignatureConstraints().getAcceptablePolicies().getId().add("ANY_POLICY");
		ValidationPolicy policy = new EtsiValidationPolicy(parameters);
		
		ValidationContextInitialization verification = new ValidationContextInitialization(diagnosticData.getSignatures().get(0), Context.SIGNATURE,
				policy);
		XmlVCI vci = verification.execute();

		for (XmlConstraint constraint : vci.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, vci.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.NO_POLICY, vci.getConclusion().getSubIndication());
		Assert.assertEquals(1, vci.getConstraint().size());
	}

	@Test
	public void testWithMandatoryPolicyAndPolicyInTheData() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithPolicy();

		ConstraintsParameters parameters = getConstraintsParameters();
		ValidationPolicy policy = new EtsiValidationPolicy(parameters);

		ValidationContextInitialization verification = new ValidationContextInitialization(diagnosticData.getSignatures().get(0), Context.SIGNATURE,
				policy);
		XmlVCI vci = verification.execute();

		for (XmlConstraint constraint : vci.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.PASSED, vci.getConclusion().getIndication());
		Assert.assertEquals(1, vci.getConstraint().size());
	}
}
