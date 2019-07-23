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
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

public class UnmarshallingTester {

	private static final Logger LOG = LoggerFactory.getLogger(UnmarshallingTester.class);

	private static ObjectMapper OBJECT_MAPPER = new ObjectMapper();

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
		mapValidationReport(reports);
	}

	public static void unmarshallDiagnosticData(Reports reports) {
		try {
			String xmlDiagnosticData = reports.getXmlDiagnosticData();
			assertTrue(Utils.isStringNotBlank(xmlDiagnosticData));
			assertNotNull(DiagnosticDataFacade.newFacade().unmarshall(xmlDiagnosticData));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Diagnostic data : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	public static void mapDiagnosticData(Reports reports) {
		ObjectMapper om = new ObjectMapper();
		JaxbAnnotationIntrospector jai = new JaxbAnnotationIntrospector(TypeFactory.defaultInstance(), true);
		om.setAnnotationIntrospector(jai);
//		om.enable(SerializationFeature.INDENT_OUTPUT);
		om.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
		om.enableDefaultTyping();

		try {
			String json = om.writeValueAsString(reports.getDiagnosticDataJaxb());
			assertNotNull(json);
			XmlDiagnosticData diagnosticDataObject = om.readerFor(XmlDiagnosticData.class).readValue(json);
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
			assertNotNull(DetailedReportFacade.newFacade().unmarshall(xmlDetailedReport));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Detailed Report : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	public static void mapDetailedReport(Reports reports) {
		try {
			String json = OBJECT_MAPPER.writeValueAsString(reports.getDetailedReportJaxb());
			assertNotNull(json);
			XmlDetailedReport detailedReportObject = OBJECT_MAPPER.readValue(json, XmlDetailedReport.class);
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
			assertNotNull(SimpleReportFacade.newFacade().unmarshall(xmlSimpleReport));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Simple Report : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	public static void mapSimpleReport(Reports reports) {
		try {
			String json = OBJECT_MAPPER.writeValueAsString(reports.getSimpleReportJaxb());
			assertNotNull(json);
			XmlSimpleReport simpleReportObject = OBJECT_MAPPER.readValue(json, XmlSimpleReport.class);
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
			assertNotNull(ValidationReportFacade.newFacade().unmarshall(xmlValidationReport));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the ETSI Validation Report : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	public static void mapValidationReport(Reports reports) {
		try {
			String json = OBJECT_MAPPER.writeValueAsString(reports.getEtsiValidationReportJaxb());
			assertNotNull(json);
			ValidationReportType validationReportObject = OBJECT_MAPPER.readValue(json, ValidationReportType.class);
			assertNotNull(validationReportObject);
		} catch (Exception e) {
			LOG.error("Unable to map the ETSI Validation Report  : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

}
