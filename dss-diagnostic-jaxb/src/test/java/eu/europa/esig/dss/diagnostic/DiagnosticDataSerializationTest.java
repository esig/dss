/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.diagnostic;

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
import com.fasterxml.jackson.module.jakarta.xmlbind.JakartaXmlBindAnnotationIntrospector;
import eu.europa.esig.dss.diagnostic.jaxb.XmlAbstractToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificateToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

// See DSS-3579
class DiagnosticDataSerializationTest {

    private static ObjectMapper objectMapper;

    @BeforeAll
    static void init() {
        objectMapper = new ObjectMapper();
        objectMapper.setAnnotationIntrospector(new JakartaXmlBindAnnotationIntrospector(TypeFactory.defaultInstance()));
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);

        SimpleModule module = new SimpleModule("Deserializers");
        module.addDeserializer(XmlTimestampedObject.class, new XmlTimestampedObjectDeserializer());
        objectMapper.registerModule(module);
    }

    @Test
    // Vanilla DSS 6.1 throws exception when QcStatements have OID.
    void serializeJsonQcStatementWithOID() throws Throwable {
        // Use XML to create XmlDiagnosticData that has QcStatement with OID.
        byte[] buffer = Files.readAllBytes(new File("src/test/resources/serialization/diagnosticData-ASIC-S_with_container.xml").toPath());
        String xml = new String(buffer);
        XmlDiagnosticData xmlDiagnosticData = DiagnosticDataFacade.newFacade().unmarshall(xml, false);
        XmlCertificateExtension ext = xmlDiagnosticData.getUsedCertificates().get(0).getCertificateExtensions().get(7);
        String oid = ext.getOID();
        assertEquals(CertificateExtensionEnum.QC_STATEMENTS.getOid(), oid);

        // Serialize
        String s = objectMapper.writeValueAsString(xmlDiagnosticData);
        assertTrue(s.contains(oid), "Missing QcStatement OID in serialized JSON string.");
    }

    @Test()
    // Vanilla DSS 6.1 throws exception when QcStatements have OID.
    void deserializeJsonQcStatementWithOID() throws Throwable {
        // Parse JSON
        byte[] buffer = Files.readAllBytes(new File("src/test/resources/serialization/diagnosticData-ASIC-S_with_container.json").toPath());
        String json = new String(buffer);

        // Deserialize
        //XmlDiagnosticData xmlDiagnosticData = objectMapper.readerFor(XmlDiagnosticData.class).readValue(json);
        XmlDiagnosticData xmlDiagnosticData = objectMapper.readValue(json, XmlDiagnosticData.class);
        assertNotNull(xmlDiagnosticData, "Failed to deserialize XmlDiagnosticData.");
        XmlCertificateExtension ext = xmlDiagnosticData.getUsedCertificates().get(0).getCertificateExtensions().get(7);
        assertEquals(CertificateExtensionEnum.QC_STATEMENTS.getOid(), ext.getOID());
    }

    @Test
    // Vanilla DSS 6.1 deserializes XmlSignerData.Parent to ID string instead of the referenced object.
    void deserializeJsonSignerDataWithParent() throws Throwable {
        // Parse JSON.
        byte[] buffer = Files.readAllBytes(new File("src/test/resources/serialization/diagnosticData-ASIC-S_with_container.json").toPath());
        String json = new String(buffer);

        // Deserialize
        XmlDiagnosticData xmlDiagnosticData = objectMapper.readerFor(XmlDiagnosticData.class).readValue(json);
        Object parent = xmlDiagnosticData.getOriginalDocuments().get(1).getParent();
        assertInstanceOf(XmlSignerData.class, parent, "SignerData[1] has invalid Parent.");
    }

    /**
     * Handle polymorphic Token.
     */
    private static class XmlTimestampedObjectDeserializer extends StdDeserializer<XmlTimestampedObject> {

        public XmlTimestampedObjectDeserializer() {
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
                case EVIDENCE_RECORD:
                    token = new XmlEvidenceRecord();
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

}