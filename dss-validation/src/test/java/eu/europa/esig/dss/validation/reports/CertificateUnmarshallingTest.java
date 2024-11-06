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
package eu.europa.esig.dss.validation.reports;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.module.jakarta.xmlbind.JakartaXmlBindAnnotationIntrospector;
import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReportFacade;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.CertificateValidator;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CertificateUnmarshallingTest {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateUnmarshallingTest.class);

	static Stream<Arguments> data() {
		File folder = new File("src/test/resources/certificates");
		Collection<File> listFiles = Utils.listFiles(folder, new String[] { "cer", "crt" }, true);
		Collection<Arguments> dataToRun = new ArrayList<>();
		for (File file : listFiles) {
			dataToRun.add(Arguments.of(file));
		}
		return dataToRun.stream();
	}

	@ParameterizedTest(name = "Validation {index} : {0}")
	@MethodSource("data")
	void test(File certToTest) {
		CertificateValidator cv = CertificateValidator.fromCertificate(DSSUtils.loadCertificate(certToTest));
		cv.setCertificateVerifier(new CommonCertificateVerifier());

		CertificateReports reports = cv.validate();
		unmarshallXmlReports(reports);
	}

	private void unmarshallXmlReports(CertificateReports reports) {
		
		unmarshallDiagnosticData(reports);
		unmarshallDetailedReport(reports);
		unmarshallSimpleReport(reports);
		
		mapDiagnosticData(reports);
		mapDetailedReport(reports);
		mapSimpleReport(reports);
		
	}

	private void unmarshallDiagnosticData(CertificateReports reports) {
		try {
			String xmlDiagnosticData = reports.getXmlDiagnosticData();
			assertTrue(Utils.isStringNotBlank(xmlDiagnosticData));
//			LOG.info(xmlDiagnosticData);
			assertNotNull(DiagnosticDataFacade.newFacade().unmarshall(xmlDiagnosticData));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Diagnostic data : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	private void mapDiagnosticData(CertificateReports reports) {
		ObjectMapper om = getObjectMapper();

		try {
			String json = om.writeValueAsString(reports.getDiagnosticDataJaxb());
			assertNotNull(json);
//			LOG.info(json);
			XmlDiagnosticData diagnosticDataObject = om.readValue(json, XmlDiagnosticData.class);
			assertNotNull(diagnosticDataObject);
		} catch (Exception e) {
			LOG.error("Unable to map the Diagnostic data : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	private void unmarshallDetailedReport(CertificateReports reports) {
		try {
			String xmlDetailedReport = reports.getXmlDetailedReport();
			assertTrue(Utils.isStringNotBlank(xmlDetailedReport));
//			LOG.info(xmlDetailedReport);
			assertNotNull(DetailedReportFacade.newFacade().unmarshall(xmlDetailedReport));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Detailed Report : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	private void mapDetailedReport(CertificateReports reports) {
		ObjectMapper om = getObjectMapper();
		try {
			String json = om.writeValueAsString(reports.getDetailedReportJaxb());
			assertNotNull(json);
//			LOG.info(json);
			XmlDetailedReport detailedReportObject = om.readValue(json, XmlDetailedReport.class);
			assertNotNull(detailedReportObject);
		} catch (Exception e) {
			LOG.error("Unable to map the Detailed Report : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	private void unmarshallSimpleReport(CertificateReports reports) {
		try {
			String xmlSimpleReport = reports.getXmlSimpleReport();
			assertTrue(Utils.isStringNotBlank(xmlSimpleReport));
//			LOG.info(xmlSimpleReport);
			assertNotNull(SimpleCertificateReportFacade.newFacade().unmarshall(xmlSimpleReport));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Simple Report : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	private void mapSimpleReport(CertificateReports reports) {
		ObjectMapper om = getObjectMapper();
		try {
			String json = om.writeValueAsString(reports.getSimpleReportJaxb());
			assertNotNull(json);
//			LOG.info(json);
			XmlSimpleCertificateReport simpleReportObject = om.readValue(json, XmlSimpleCertificateReport.class);
			assertNotNull(simpleReportObject);
		} catch (Exception e) {
			LOG.error("Unable to map the Simple Report : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	private static ObjectMapper getObjectMapper() {
		ObjectMapper om = new ObjectMapper();
		JakartaXmlBindAnnotationIntrospector jai = new JakartaXmlBindAnnotationIntrospector(TypeFactory.defaultInstance());
		om.setAnnotationIntrospector(jai);
		om.enable(SerializationFeature.INDENT_OUTPUT);
		return om;
	}
}
