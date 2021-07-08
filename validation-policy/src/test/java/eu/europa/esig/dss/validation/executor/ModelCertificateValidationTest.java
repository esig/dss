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

import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.CertificateQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.Model;
import eu.europa.esig.dss.policy.jaxb.ModelConstraint;
import eu.europa.esig.dss.validation.executor.certificate.DefaultCertificateProcessExecutor;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JUnit test implementation for model based certificate validation.
 *
 * @author akoepe
 * @version 1.0
 */
public class ModelCertificateValidationTest extends ModelAbstractlValidation {
	private static final SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy");

	private static final Stream<Arguments> data() throws Exception {
		final List<Arguments> data = new ArrayList<>();

		data.add( Arguments.of( new TestCase( TestData.DATA_1, Model.SHELL, sdf.parse("22-05-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.PASSED, 		"D569:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_1, Model.SHELL, sdf.parse("18-06-2017"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.PASSED,		"D569:" + Indication.INDETERMINATE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_1, Model.SHELL, sdf.parse("23-05-2018"), CertificateQualification.CERT_FOR_ESIG, 	    "47F7:" + Indication.INDETERMINATE, "D569:" + Indication.INDETERMINATE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_1, Model.SHELL, sdf.parse("01-05-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.INDETERMINATE, "D569:" + Indication.PASSED ) ) );
		
		data.add( Arguments.of( new TestCase( TestData.DATA_1, Model.CHAIN, sdf.parse("22-05-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.PASSED,		"D569:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_1, Model.CHAIN, sdf.parse("18-06-2017"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.PASSED,		"D569:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_1, Model.CHAIN, sdf.parse("23-05-2018"), CertificateQualification.CERT_FOR_ESIG, 	    "47F7:" + Indication.INDETERMINATE, "D569:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_1, Model.CHAIN, sdf.parse("01-05-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.INDETERMINATE, "D569:" + Indication.PASSED ) ) );
		
		data.add( Arguments.of( new TestCase( TestData.DATA_1, Model.HYBRID, sdf.parse("22-05-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.PASSED,		 "D569:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_1, Model.HYBRID, sdf.parse("18-06-2017"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.PASSED,		 "D569:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_1, Model.HYBRID, sdf.parse("23-05-2018"), CertificateQualification.CERT_FOR_ESIG, 	     "47F7:" + Indication.INDETERMINATE, "D569:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_1, Model.HYBRID, sdf.parse("01-05-2016"), CertificateQualification.QCERT_FOR_ESIG_QSCD, "47F7:" + Indication.INDETERMINATE, "D569:" + Indication.PASSED ) ) );

		
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("22-05-2016"), CertificateQualification.NA, "9532:" + Indication.PASSED,        "B729:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("18-06-2017"), CertificateQualification.NA, "9532:" + Indication.PASSED,        "B729:" + Indication.INDETERMINATE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("18-11-2020"), CertificateQualification.NA, "9532:" + Indication.INDETERMINATE, "B729:" + Indication.INDETERMINATE) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.SHELL, sdf.parse("01-05-2016"), CertificateQualification.NA, "9532:" + Indication.INDETERMINATE, "B729:" + Indication.PASSED ) ) );

		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("22-05-2016"), CertificateQualification.NA, "9532:" + Indication.PASSED,		   "B729:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("18-06-2017"), CertificateQualification.NA, "9532:" + Indication.PASSED,		   "B729:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("18-11-2020"), CertificateQualification.NA, "9532:" + Indication.INDETERMINATE, "B729:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.CHAIN, sdf.parse("01-05-2016"), CertificateQualification.NA, "9532:" + Indication.INDETERMINATE, "B729:" + Indication.PASSED ) ) );
		
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("22-05-2016"), CertificateQualification.NA, "9532:" + Indication.PASSED,		"B729:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("18-06-2017"), CertificateQualification.NA, "9532:" + Indication.PASSED,		"B729:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("18-11-2020"), CertificateQualification.NA, "9532:" + Indication.INDETERMINATE, "B729:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_2, Model.HYBRID, sdf.parse("01-05-2016"), CertificateQualification.NA, "9532:" + Indication.INDETERMINATE, "B729:" + Indication.PASSED ) ) );

		
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("22-05-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.PASSED,        "0504:" + Indication.PASSED       , "BA85:" + Indication.INDETERMINATE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("16-11-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.PASSED,        "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("01-05-2016"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED, "BA85:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("18-11-2029"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.INDETERMINATE, "BA85:" + Indication.INDETERMINATE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.SHELL, sdf.parse("01-05-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) ) );

		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("22-05-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.PASSED,        "0504:" + Indication.PASSED,        "BA85:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("16-11-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.PASSED,        "0504:" + Indication.PASSED,        "BA85:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("01-05-2016"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("18-11-2029"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.PASSED ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.CHAIN, sdf.parse("01-05-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.PASSED ) ) );
		
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("22-05-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.PASSED,        "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("16-11-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.PASSED,        "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("01-05-2016"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("18-11-2029"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) ) );
		data.add( Arguments.of( new TestCase( TestData.DATA_3, Model.HYBRID, sdf.parse("01-05-2017"), CertificateQualification.CERT_FOR_ESIG, "DBCF:" + Indication.INDETERMINATE, "0504:" + Indication.PASSED,        "BA85:" + Indication.INDETERMINATE ) ) );

		return data.stream();
	}

	@ParameterizedTest(name = "{index}: inputData - {0}")
	@MethodSource("data")
	public void testModelBasedCertificateChain(final TestCase testCase) throws Exception {
		
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
		assertEquals(testCase.getTestData().getSignerCertificateIdentifier(), signerCertId);
		
		DefaultCertificateProcessExecutor executor = new DefaultCertificateProcessExecutor();
		executor.setCertificateId(signerCertId);
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(policy);
		executor.setCurrentTime(diagnosticData.getValidationDate());

		CertificateReports reports = executor.execute();
		
		XmlDetailedReport detailedReport = reports.getDetailedReportJaxb();
		assertNotNull(detailedReport);
		assertNotNull(detailedReport.getBasicBuildingBlocks());
		assertTrue(!detailedReport.getBasicBuildingBlocks().isEmpty());
		
		Map<String, String> messages = new HashMap<>();
		for (XmlBasicBuildingBlocks bb : detailedReport.getBasicBuildingBlocks()) {
			for (XmlSubXCV sub : bb.getXCV().getSubXCV()) {
				String id = sub.getId().substring(sub.getId().length() - 4);
				Indication ind = sub.getConclusion().getIndication();
				if (!Indication.PASSED.equals(ind)) {
					StringBuilder buf = new StringBuilder();
					for (XmlMessage n : sub.getConclusion().getInfos()) {
						if (buf.length() > 0) {
							buf.append("\n\t");
						}
						buf.append(n.getValue());
					}
					String str = buf.length() > 0 ? ("Info:\n" + buf.toString()) : "";
					
					buf = new StringBuilder();
					for (XmlMessage n : sub.getConclusion().getWarnings()) {
						if (buf.length() > 0) {
							buf.append("\n\t");
						}
						buf.append(n.getValue());
					}
					str += buf.length() > 0 ? (str.length() > 0 ? "\n" : "") + "Warn:\n" + buf.toString() : str;
					
					buf = new StringBuilder();
					for (XmlMessage n : sub.getConclusion().getErrors()) {
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

		eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		assertNotNull(simpleReport.getCertificateIds());
		assertEquals(testCase.getTestData().getNumberOfInvolvedCertificates(), simpleReport.getCertificateIds().size());
		for (String id : simpleReport.getCertificateIds()) {
			Indication expected = (Indication)testCase.getExpectedCertResult(id);
			if (expected == null) {
				continue;
			}
			
			Indication got = simpleReport.getCertificateIndication(id);
			String key = id.substring(id.length() - 4);
			assertEquals(expected, got, "[" + key + "] Missmatched expected Indication " + expected + ", got " + got + ".\n" + messages.getOrDefault(key, ""));
		}
		assertEquals(testCase.getQualification(), simpleReport.getQualificationAtValidationTime());
	}
}
