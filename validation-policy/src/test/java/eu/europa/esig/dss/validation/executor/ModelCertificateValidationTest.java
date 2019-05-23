package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.FileInputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.jaxb.detailedreport.XmlName;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSubXCV;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.validation.CertificateQualification;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.Model;
import eu.europa.esig.jaxb.policy.ModelConstraint;

/**
 * JUnit test implementation for model based certificate validation.
 *
 * @author akoepe
 * @version 1.0
 */
@RunWith(value = Parameterized.class)
public class ModelCertificateValidationTest extends ModelAbstractlValidation {
	private static final SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy");

	@Parameters(name = "{index}: inputData - {0}")
	public static final List<Object[]> data() throws Exception {
		final List<Object[]> data = new ArrayList<>();

		data.add( new Object[] { new TestCase( TestData.DATA_1, Model.SHELL, sdf.parse("22-05-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.PASSED, 		"D569:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_1, Model.SHELL, sdf.parse("18-11-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.PASSED,		"D569:" + Indication.INDETERMINATE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_1, Model.SHELL, sdf.parse("23-05-2018"), CertificateQualification.CERT_FOR_ESIG, 	    "47F7:" + Indication.INDETERMINATE, "D569:" + Indication.INDETERMINATE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_1, Model.SHELL, sdf.parse("01-05-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.INDETERMINATE, "D569:" + Indication.PASSED ) } );
		
		data.add( new Object[] { new TestCase( TestData.DATA_1, Model.CHAIN, sdf.parse("22-05-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.PASSED,		"D569:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_1, Model.CHAIN, sdf.parse("18-11-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.PASSED,		"D569:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_1, Model.CHAIN, sdf.parse("23-05-2018"), CertificateQualification.CERT_FOR_ESIG, 	    "47F7:" + Indication.INDETERMINATE, "D569:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_1, Model.CHAIN, sdf.parse("01-05-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.INDETERMINATE, "D569:" + Indication.PASSED ) } );
		
		data.add( new Object[] { new TestCase( TestData.DATA_1, Model.HYBRID, sdf.parse("22-05-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.PASSED,		 "D569:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_1, Model.HYBRID, sdf.parse("18-11-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.PASSED,		 "D569:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_1, Model.HYBRID, sdf.parse("23-05-2018"), CertificateQualification.CERT_FOR_ESIG, 	     "47F7:" + Indication.INDETERMINATE, "D569:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_1, Model.HYBRID, sdf.parse("01-05-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.INDETERMINATE, "D569:" + Indication.PASSED ) } );

		
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("22-05-2016"), CertificateQualification.NA, "9532:" + Indication.PASSED,        "B729:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("18-11-2016"), CertificateQualification.NA, "9532:" + Indication.PASSED,        "B729:" + Indication.INDETERMINATE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("18-11-2020"), CertificateQualification.NA, "9532:" + Indication.INDETERMINATE, "B729:" + Indication.INDETERMINATE) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("01-05-2016"), CertificateQualification.NA, "9532:" + Indication.INDETERMINATE, "B729:" + Indication.PASSED ) } );

		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("22-05-2016"), CertificateQualification.NA, "9532:" + Indication.PASSED,		   "B729:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("18-11-2016"), CertificateQualification.NA, "9532:" + Indication.PASSED,		   "B729:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("18-11-2020"), CertificateQualification.NA, "9532:" + Indication.INDETERMINATE, "B729:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("01-05-2016"), CertificateQualification.NA, "9532:" + Indication.INDETERMINATE, "B729:" + Indication.PASSED ) } );
		
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("22-05-2016"), CertificateQualification.NA, "9532:" + Indication.PASSED,		"B729:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("18-11-2016"), CertificateQualification.NA, "9532:" + Indication.PASSED,		"B729:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("18-11-2020"), CertificateQualification.NA, "9532:" + Indication.INDETERMINATE, "B729:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("01-05-2016"), CertificateQualification.NA, "9532:" + Indication.INDETERMINATE, "B729:" + Indication.PASSED ) } );

		
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("22-05-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.PASSED,        "0504:" + Indication.PASSED       , "BA85:" + Indication.INDETERMINATE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("16-11-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.PASSED,        "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("01-05-2016"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.INDETERMINATE, "BA85:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("18-11-2029"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.INDETERMINATE, "BA85:" + Indication.INDETERMINATE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("01-05-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) } );

		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("22-05-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.PASSED,        "0504:" + Indication.PASSED,        "BA85:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("16-11-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.PASSED,        "0504:" + Indication.PASSED,        "BA85:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("01-05-2016"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("18-11-2029"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.PASSED ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("01-05-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.PASSED ) } );
		
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("22-05-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.PASSED,        "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("16-11-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.PASSED,        "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("01-05-2016"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("18-11-2029"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) } );
		data.add( new Object[] { new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("01-05-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) } );

		return data;
	}
	
	private final TestCase testCase;
	private final EtsiValidationPolicy policy;
	private final DiagnosticData diagnosticData;
	
	/**
	 * Constructor.
	 * 
	 * @param testCase the test case data that has to be used
	 * @throws Exception if any error occurs
	 */
	public ModelCertificateValidationTest(final TestCase testCase) throws Exception {
		this.testCase = testCase;
		
		FileInputStream policyFis = new FileInputStream(testCase.getTestData().getPolicy());
		ConstraintsParameters policyJaxB = getJAXBObjectFromString(policyFis, ConstraintsParameters.class, "/xsd/policy.xsd");

		ModelConstraint mc = new ModelConstraint();
		mc.setValue(testCase.getModel());
		policyJaxB.setModel(mc);
		policy = new EtsiValidationPolicy(policyJaxB);

		FileInputStream fis = new FileInputStream(testCase.getTestData().getDiagnosticData());
		diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);
		assertNotNull(diagnosticData.getSignatures());
		assertTrue(!diagnosticData.getSignatures().isEmpty());
		
		diagnosticData.setValidationDate(testCase.getValidationDate());
	}

	@Test
	public void testModelBasedCertificateChain() throws Exception {
		final String signerCertId = diagnosticData.getSignatures().get(0).getSigningCertificate().getId();
		assertTrue(testCase.getTestData().getSignerCertificateIdentifier().equals(signerCertId));
		
		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setCertificateId(signerCertId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(policy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();
		
		DetailedReport detailedReport = reports.getDetailedReportJaxb();
		assertNotNull(detailedReport);
		assertNotNull(detailedReport.getBasicBuildingBlocks());
		assertTrue(!detailedReport.getBasicBuildingBlocks().isEmpty());
		
		Map<String, String> messages = new HashMap<>();
		for (XmlBasicBuildingBlocks bb : detailedReport.getBasicBuildingBlocks()) {
			for (XmlSubXCV sub : bb.getXCV().getSubXCV()) {
				String id = sub.getId().substring(sub.getId().length() - 4);
				Indication ind = sub.getConclusion().getIndication();
				if (!Indication.PASSED.equals(ind)) {
					StringBuffer buf = new StringBuffer("");
					for (XmlName n : sub.getConclusion().getInfos()) {
						if (buf.length() > 0) {
							buf.append("\n\t");
						}
						buf.append(n.getValue());
					}
					String str = buf.length() > 0 ? ("Info:\n" + buf.toString()) : "";
					
					buf = new StringBuffer("");
					for (XmlName n : sub.getConclusion().getWarnings()) {
						if (buf.length() > 0) {
							buf.append("\n\t");
						}
						buf.append(n.getValue());
					}
					str += buf.length() > 0 ? (str.length() > 0 ? "\n" : "") + "Warn:\n" + buf.toString() : str;
					
					buf = new StringBuffer("");
					for (XmlName n : sub.getConclusion().getErrors()) {
						if (buf.length() > 0) {
							buf.append("\n\t");
						}
						buf.append(n.getValue());
					}
					str += buf.length() > 0 ? (str.length() > 0 ? "\n" : "") + "Err :\n" + buf.toString() : str;
					
					if (!str.isEmpty()) {
						messages.put(id, str);
					}
				}
				
//				final Object exp = testCase.getExpectedCertResult(id);
//				if (exp != null && exp instanceof Indication) {
//					assertTrue(((Indication)exp).equals(ind));
//				}
			}
		}

		eu.europa.esig.dss.validation.reports.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		assertNotNull(simpleReport.getCertificateIds());
		assertEquals(testCase.getTestData().getNumberOfInvolvedCertificates(), simpleReport.getCertificateIds().size());
		for (String id : simpleReport.getCertificateIds()) {
			Indication expected = (Indication)testCase.getExpectedCertResult(id);
			if (expected == null) {
				continue;
			}
			
			Indication got = simpleReport.getCertificateIndication(id);
			String key = id.substring(id.length() - 4, id.length());
			assertEquals("[" + key + "] Missmatched expected Indication " + expected + ", got " + got + ".\n" + messages.getOrDefault(key, ""), expected, got);
		}
		assertEquals(testCase.getQualification(), simpleReport.getQualificationAtValidationTime());
	}
}
