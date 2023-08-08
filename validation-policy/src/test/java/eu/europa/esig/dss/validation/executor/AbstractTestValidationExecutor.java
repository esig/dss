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

import com.fasterxml.jackson.core.JsonParser;
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
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificateToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.simplereport.SimpleReportFacade;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.ValidationReportFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractTestValidationExecutor {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractTestValidationExecutor.class);
	
	protected ValidationPolicy loadPolicy(String policyConstraintFile) throws Exception {
		return ValidationPolicyFacade.newFacade().getValidationPolicy(new File(policyConstraintFile));
	}

	protected ValidationPolicy loadDefaultPolicy() throws Exception {
		return ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
	}
	
	protected ConstraintsParameters getConstraintsParameters(File file) throws Exception {
		return ValidationPolicyFacade.newFacade().unmarshall(file);
	}

	protected void checkReports(Reports reports) throws Exception {
		assertNotNull(reports);
		assertNotNull(reports.getDiagnosticData());
		assertNotNull(reports.getDiagnosticDataJaxb());
		assertNotNull(reports.getSimpleReport());
		assertNotNull(reports.getSimpleReportJaxb());
		assertNotNull(reports.getDetailedReport());
		assertNotNull(reports.getDetailedReportJaxb());
		assertNotNull(reports.getEtsiValidationReportJaxb());
		unmarshallXmlReports(reports);
	}

	protected void unmarshallXmlReports(Reports reports) {
		unmarshallDiagnosticData(reports);
		unmarshallDetailedReport(reports);
		unmarshallSimpleReport(reports);
		unmarshallValidationReport(reports);

		mapDiagnosticData(reports);
		mapDetailedReport(reports);
		mapSimpleReport(reports);
	}

	protected void unmarshallDiagnosticData(Reports reports) {
		try {
			String xmlDiagnosticData = reports.getXmlDiagnosticData();
			assertTrue(Utils.isStringNotBlank(xmlDiagnosticData));
			assertNotNull(DiagnosticDataFacade.newFacade().unmarshall(xmlDiagnosticData));
		} catch (Exception e) {
			LOG.error("Unable to unmarshall the Diagnostic data : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	protected static void mapDiagnosticData(Reports reports) {
		ObjectMapper om = getObjectMapper();

		SimpleModule module = new SimpleModule("XmlTimestampedObjectDeserializerModule");
		XmlTimestampedObjectDeserializer deserializer = new XmlTimestampedObjectDeserializer();
		module.addDeserializer(XmlTimestampedObject.class, deserializer);
		om.registerModule(module);

		try {
			String json = om.writeValueAsString(reports.getDiagnosticDataJaxb());
			assertNotNull(json);
			XmlDiagnosticData diagnosticDataObject = om.readValue(json, XmlDiagnosticData.class);
			assertNotNull(diagnosticDataObject);
		} catch (Exception e) {
			LOG.error("Unable to map the Diagnostic data : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	private void unmarshallDetailedReport(Reports reports) {
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
		ObjectMapper om = getObjectMapper();
		try {
			String json = om.writeValueAsString(reports.getDetailedReportJaxb());
			assertNotNull(json);
			XmlDetailedReport detailedReportObject = om.readValue(json, XmlDetailedReport.class);
			assertNotNull(detailedReportObject);
		} catch (Exception e) {
			LOG.error("Unable to map the Detailed Report : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	private void unmarshallSimpleReport(Reports reports) {
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
		ObjectMapper om = getObjectMapper();
		try {
			String json = om.writeValueAsString(reports.getSimpleReportJaxb());
			assertNotNull(json);
			XmlSimpleReport simpleReportObject = om.readValue(json, XmlSimpleReport.class);
			assertNotNull(simpleReportObject);
		} catch (Exception e) {
			LOG.error("Unable to map the Simple Report : " + e.getMessage(), e);
			fail(e.getMessage());
		}
	}

	public void unmarshallValidationReport(Reports reports) {
		try {
			String xmlValidationReport = reports.getXmlValidationReport();
			assertTrue(Utils.isStringNotBlank(xmlValidationReport));
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
		public XmlTimestampedObject deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
			ObjectMapper mapper = (ObjectMapper) jp.getCodec();
			ObjectNode root = mapper.readTree(jp);
			JsonNode categoryNode = root.get("Category");
			TimestampedObjectType category = TimestampedObjectType.valueOf(categoryNode.textValue());
			JsonNode tokenNode = root.get("Token");

			XmlTimestampedObject timestampedObject = new XmlTimestampedObject();
			timestampedObject.setCategory(category);

			XmlAbstractToken token;
			switch (category) {
				case SIGNATURE:
					token = new eu.europa.esig.dss.diagnostic.jaxb.XmlSignature();
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
				case ORPHAN_CERTIFICATE:
					token = new XmlOrphanCertificateToken();
					break;
				case ORPHAN_REVOCATION:
					token = new XmlOrphanRevocationToken();
					break;
				default:
					throw new InvalidFormatException(jp, "Unsupported category value " + category, category, TimestampedObjectType.class);
			}

			token.setId(tokenNode.textValue());
			timestampedObject.setToken(token);
			return timestampedObject;
		}

	}

	protected boolean checkMessageValuePresence(List<Message> messages, String messageValue) {
		return messages.stream().map(Message::getValue).collect(Collectors.toList()).contains(messageValue);
	}

	protected List<Message> convert(List<eu.europa.esig.dss.detailedreport.jaxb.XmlMessage> messages) {
		return messages.stream().map(m -> new Message(m.getKey(), m.getValue())).collect(Collectors.toList());
	}

	protected List<Message> convertMessages(List<eu.europa.esig.dss.simplereport.jaxb.XmlMessage> messages) {
		return messages.stream().map(m -> new Message(m.getKey(), m.getValue())).collect(Collectors.toList());
	}

}
