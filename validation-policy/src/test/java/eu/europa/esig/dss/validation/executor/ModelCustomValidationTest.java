package eu.europa.esig.dss.validation.executor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.Model;
import eu.europa.esig.dss.policy.jaxb.ModelConstraint;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * JUnit test implementation for model based custom validation.
 *
 * @author akoepe
 * @version 1.0
 */
public class ModelCustomValidationTest extends ModelAbstractlValidation {
	private static final SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy");

	public static final Stream<Arguments> data() throws Exception {
		final List<Arguments> data = new ArrayList<>();
		
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("22-05-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("18-11-2016"), CertificateQualification.NA, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("18-11-2020"), CertificateQualification.NA, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.TRY_LATER ) ) ); // Revoc not fresh
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("01-05-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) ) );

		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("22-05-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("18-11-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("18-11-2020"), CertificateQualification.NA, "ind:" + Indication.INDETERMINATE, "sub:" +  SubIndication.TRY_LATER ) ) ); // Revoc not fresh
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("01-05-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) ) );
		
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("22-05-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("18-11-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("18-11-2020"), CertificateQualification.NA, "ind:" + Indication.INDETERMINATE, "sub:" +  SubIndication.TRY_LATER ) ) ); // Revoc not fresh
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("01-05-2016"), CertificateQualification.NA, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) ) );
		
		
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("22-05-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("16-11-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("01-05-2016"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("18-11-2029"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("01-05-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) ) );

		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("22-05-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("16-11-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("01-05-2016"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("18-11-2029"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("01-05-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) ) );
		
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("22-05-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("16-11-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("01-05-2016"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("18-11-2029"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.INDETERMINATE, "sub:" + SubIndication.NO_POE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("01-05-2017"), CertificateQualification.CERT_FOR_ESIG, "ind:" + Indication.TOTAL_FAILED,  "sub:" + SubIndication.NOT_YET_VALID ) ) );

		return data.stream();
	}

	@ParameterizedTest(name = "{index}")
	@MethodSource("data")
	public void testModelBasedSignedDocument(TestCase testCase) throws Exception {
		
		ConstraintsParameters policyJaxB = ValidationPolicyFacade.newFacade().unmarshall(new File(testCase.getTestData().getPolicy()));

		ModelConstraint mc = new ModelConstraint();
		mc.setValue(testCase.getModel());
		policyJaxB.setModel(mc);
		ValidationPolicy policy = new EtsiValidationPolicy(policyJaxB);

		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File(testCase.getTestData().getDiagnosticData()));
		assertNotNull(diagnosticData);
		assertNotNull(diagnosticData.getSignatures());
		assertTrue(!diagnosticData.getSignatures().isEmpty());
		
		diagnosticData.setValidationDate(testCase.getValidationDate());
		
		final String signerCertId = diagnosticData.getSignatures().get(0).getSigningCertificate().getCertificate().getId();
		assertTrue(testCase.getTestData().getSignerCertificateIdentifier().equals(signerCertId));
		
		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(policy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		Reports reports = executor.execute();
//		reports.print();
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
