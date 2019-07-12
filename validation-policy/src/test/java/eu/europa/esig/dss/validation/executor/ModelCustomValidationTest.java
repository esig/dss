package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.detailedreport.XmlDetailedReport;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDiagnosticData;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.Model;
import eu.europa.esig.jaxb.policy.ModelConstraint;
import eu.europa.esig.jaxb.policy.ValidationPolicyFacade;

/**
 * JUnit test implementation for model based custom validation.
 *
 * @author akoepe
 * @version 1.0
 */
@RunWith(value = Parameterized.class)
public class ModelCustomValidationTest extends ModelAbstractlValidation {
	private static final SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy");

	@Parameters(name = "{index}: inputData - {0}")
	public static final List<Object[]> data() throws Exception {
		final List<Object[]> data = new ArrayList<>();
		
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("22-05-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("18-11-2016"), CertificateQualification.NA, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("18-11-2020"), CertificateQualification.NA, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("01-05-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) } );

		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("22-05-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("18-11-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("18-11-2020"), CertificateQualification.NA, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("01-05-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) } );
		
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("22-05-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("18-11-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("18-11-2020"), CertificateQualification.NA, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("01-05-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) } );
		
		
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("22-05-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("16-11-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("01-05-2016"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("18-11-2029"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("01-05-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) } );

		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("22-05-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("16-11-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("01-05-2016"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("18-11-2029"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("01-05-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) } );
		
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("22-05-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("16-11-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("01-05-2016"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("18-11-2029"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("01-05-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) } );

		return data;
	}
	
	
	private final TestCase testCase;
	private final EtsiValidationPolicy policy;
	private final XmlDiagnosticData diagnosticData;
	
	/**
	 * Constructor.
	 * 
	 * @param testCase the test case data that has to be used
	 * @throws Exception if any error occurs
	 */
	public ModelCustomValidationTest(final TestCase testCase) throws Exception {
		this.testCase = testCase;
		
		ConstraintsParameters policyJaxB = ValidationPolicyFacade.newFacade().unmarshall(new File(testCase.getTestData().getPolicy()));

		ModelConstraint mc = new ModelConstraint();
		mc.setValue(testCase.getModel());
		policyJaxB.setModel(mc);
		policy = new EtsiValidationPolicy(policyJaxB);

		diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File(testCase.getTestData().getDiagnosticData()));
		assertNotNull(diagnosticData);
		assertNotNull(diagnosticData.getSignatures());
		assertTrue(!diagnosticData.getSignatures().isEmpty());
		
		diagnosticData.setValidationDate(testCase.getValidationDate());
	}

	@Test
	public void testModelBasedSignedDocument() throws Exception {
		final String signerCertId = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate().getId();
		assertTrue(testCase.getTestData().getSignerCertificateIdentifier().equals(signerCertId));
		
		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(policy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
		assertNotNull(reports);
		
		XmlDetailedReport detailedReport = reports.getDetailedReportJaxb();
		assertNotNull(detailedReport);

		XmlSimpleReport simpleReport = reports.getSimpleReportJaxb();
		assertNotNull(simpleReport);
		assertTrue(1 == simpleReport.getSignaturesCount());
		assertNotNull(simpleReport.getSignature().get(0));
		assertEquals(testCase.getExpectedCertResult("ind"), simpleReport.getSignature().get(0).getIndication());
		
		if (testCase.getExpectedCertResult("sub") != null) {
			assertEquals(testCase.getExpectedCertResult("sub"), simpleReport.getSignature().get(0).getSubIndication());
		}
	}
}
