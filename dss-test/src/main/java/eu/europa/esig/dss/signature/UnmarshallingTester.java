package eu.europa.esig.dss.signature;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationIntrospector;

import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.simplereport.SimpleReportFacade;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.ValidationReportFacade;

public class UnmarshallingTester {

	private static final Logger LOG = LoggerFactory.getLogger(UnmarshallingTester.class);

	public static void unmarshallXmlReports(Reports reports) {

		// XML
		unmarshallDiagnosticData(reports);
		unmarshallDetailedReport(reports);
		unmarshallSimpleReport(reports);
		unmarshallValidationReport(reports);

		// JSON
		mapDiagnosticData(reports);
		mapDetailedReport(reports);
		mapSimpleReport(reports);
		// JSON for ETSI VR is skipped
		// mapValidationReport(reports);
	}

	public static void unmarshallDiagnosticData(Reports reports) {
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

	public static void mapDiagnosticData(Reports reports) {
		ObjectMapper om = getObjectMapper();
		try {
			String json = om.writeValueAsString(reports.getDiagnosticDataJaxb());
			assertNotNull(json);
//			LOG.info(json);
			XmlDiagnosticData diagnosticDataObject = om.readValue(json, XmlDiagnosticData.class);
			assertNotNull(diagnosticDataObject);
		} catch (Exception e) {
			LOG.error("Unable to readValue the Diagnostic data : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	public static void unmarshallDetailedReport(Reports reports) {
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

	public static void mapDetailedReport(Reports reports) {
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

	public static void unmarshallSimpleReport(Reports reports) {
		try {
			String xmlSimpleReport = reports.getXmlSimpleReport();
			assertTrue(Utils.isStringNotBlank(xmlSimpleReport));
//			LOG.info(xmlSimpleReport);
			assertNotNull(SimpleReportFacade.newFacade().unmarshall(xmlSimpleReport));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Simple Report : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	public static void mapSimpleReport(Reports reports) {
		ObjectMapper om = getObjectMapper();
		try {
			String json = om.writeValueAsString(reports.getSimpleReportJaxb());
			assertNotNull(json);
//			LOG.info(json);
			XmlSimpleReport simpleReportObject = om.readValue(json, XmlSimpleReport.class);
			assertNotNull(simpleReportObject);
		} catch (Exception e) {
			LOG.error("Unable to map the Simple Report : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	public static void unmarshallValidationReport(Reports reports) {
		try {
			String xmlValidationReport = reports.getXmlValidationReport();
			assertTrue(Utils.isStringNotBlank(xmlValidationReport));
//			LOG.info(xmlValidationReport);
			assertNotNull(ValidationReportFacade.newFacade().unmarshall(xmlValidationReport));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the ETSI Validation Report : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	private static ObjectMapper getObjectMapper() {
		ObjectMapper om = new ObjectMapper();
		JaxbAnnotationIntrospector jai = new JaxbAnnotationIntrospector(TypeFactory.defaultInstance());
		om.setAnnotationIntrospector(jai);
		om.enable(SerializationFeature.INDENT_OUTPUT);
		return om;
	}

}
