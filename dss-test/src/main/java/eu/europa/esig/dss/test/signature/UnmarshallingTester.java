package eu.europa.esig.dss.test.signature;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationIntrospector;

import eu.europa.esig.dss.detailedreport.DetailedReportFacade;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAbstractToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
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

		SimpleModule module = new SimpleModule("XmlTimestampedObjectDeserializerModule");
		XmlTimestampedObjectDeserializer deserializer = new XmlTimestampedObjectDeserializer();
		module.addDeserializer(XmlTimestampedObject.class, deserializer);
		om.registerModule(module);

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

	private static class XmlTimestampedObjectDeserializer extends StdDeserializer<XmlTimestampedObject> {

		private static final long serialVersionUID = -5743323649165950906L;

		protected XmlTimestampedObjectDeserializer() {
			super(XmlTimestampedObject.class);
		}

		@Override
		public XmlTimestampedObject deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException, JsonProcessingException {
			ObjectMapper mapper = (ObjectMapper) jp.getCodec();
			ObjectNode root = (ObjectNode) mapper.readTree(jp);
			JsonNode categoryNode = root.get("Category");
			TimestampedObjectType category = TimestampedObjectType.valueOf(categoryNode.textValue());
			JsonNode tokenNode = root.get("Token");

			XmlTimestampedObject timestampedObject = new XmlTimestampedObject();
			timestampedObject.setCategory(category);

			XmlAbstractToken token = null;
			switch (category) {
			case SIGNATURE:
				token = new XmlSignature();
				break;
			case CERTIFICATE:
				token = new XmlCertificate();
				break;
			case REVOCATION:
				token = new XmlRevocation();
				break;
			case TIMESTAMP:
				token = new XmlTimestamp();
				break;
			case SIGNED_DATA:
				token = new XmlSignerData();
				break;
			case ORPHAN:
				token = new XmlOrphanToken();
				break;
			default:
				throw new InvalidFormatException(jp, "Unsupported category value " + category, category, TimestampedObjectType.class);
			}

			token.setId(tokenNode.textValue());
			timestampedObject.setToken(token);
			return timestampedObject;
		}

	}

}
