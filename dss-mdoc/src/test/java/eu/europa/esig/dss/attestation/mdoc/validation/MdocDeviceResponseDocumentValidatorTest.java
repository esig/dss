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
package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.attestation.common.validation.DefaultAttestationDocumentValidator;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.test.validation.AbstractTestDocumentValidator;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocDeviceResponseDocumentValidatorTest extends AbstractTestDocumentValidator {

    private static final DSSDocument MINIMAL_DEVICE_RESPONSE = buildMinimalDeviceResponse();

    private static DSSDocument buildMinimalDeviceResponse() {
        CBORValue issuerSigned = CBOR.map()
                .put("version", CBOR.text("1.0"))
                .put("status", 0)
                .value();
        return new InMemoryDocument(CBORUtils.serializeCbor(issuerSigned));
    }

    private static CBORValue buildDocument() {
        return CBOR.map()
                .put("docType", "org.iso.18013.5.1.mDL")
                .put("issuerSigned", buildIssuerSigned())
                .put("deviceSigned", buildDeviceSigned())
                .value();
    }

    private static CBORValue buildIssuerSigned() {
        return CBOR.map()
                .put("issuerAuth", buildCoseSign1())
                .value();
    }

    private static CBORValue buildDeviceSigned() {
        return CBOR.map()
                .put("nameSpaces", CBOR.map().value().encodeToBytes())
                .put("deviceAuth", buildCoseSign1())
                .value();
    }

    private static CBORValue buildCoseSign1() {
        return CBOR.array(4)
                .add(CBOR.bytes(new byte[0]))
                .add(CBOR.map().value())
                .add(createEmptyMSO())
                .add(CBOR.bytes(new byte[0]))
                .value();
    }

    private static CBORValue createEmptyMSO() {
        return CBOR.bytes(CBORUtils.serializeCbor(CBOR.map().value()));
    }

    private static CBORValue buildDocumentError() {
        return CBOR.map()
                .put("org.iso.23220.1.mID", 1)
                .value();
    }

    @Test
    void test() {
        MdocDeviceResponseDocumentValidator validator = new MdocDeviceResponseDocumentValidator();

        DSSDocument mdoc = MINIMAL_DEVICE_RESPONSE;
        assertTrue(validator.isSupported(mdoc));

        CBORValue allKeys = CBOR.map()
                .put("version", CBOR.text("1.0"))
                .put("documents", CBOR.array().add(buildDocument()).value())
                .put("documentErrors", CBOR.array().add(buildDocumentError()).value())
                .put("status", 0)
                .value();
        mdoc = new InMemoryDocument(CBORUtils.serializeCbor(allKeys));
        assertTrue(validator.isSupported(mdoc));

        mdoc = new FileDocument("src/test/resources/validation/mdocRefImpl.mdoc");
        assertTrue(validator.isSupported(mdoc));

        CBORValue wrongKeyMap = CBOR.map()
                .put("test", 1)
                .value();
        DSSDocument wrong = new InMemoryDocument(CBORUtils.serializeCbor(wrongKeyMap));
        assertFalse(validator.isSupported(wrong));
        wrong = new FileDocument("src/test/resources/validation/mdocIssuerSigned.cbor");
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument(CBORUtils.serializeCbor(CBOR.array().value()));
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("hello".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("<xml/>".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument(new byte[]{});
        assertFalse(validator.isSupported(wrong));
        wrong = InMemoryDocument.createEmptyDocument();
        assertFalse(validator.isSupported(wrong));
    }

    @Override
    protected SignedDocumentValidator initEmptyValidator() {
        return new MdocDeviceResponseDocumentValidator();
    }

    @Override
    protected SignedDocumentValidator initValidator(DSSDocument document) {
        return new MdocDeviceResponseDocumentValidator(document);
    }

    @Override
    protected List<DSSDocument> getValidDocuments() {
        return Collections.singletonList(new FileDocument("src/test/resources/validation/mdocRefImpl.mdoc"));
    }

    @Override
    protected DSSDocument getMalformedDocument() {
        return new InMemoryDocument(CBORUtils.serializeCbor(CBOR.array().value()));
    }

    @Override
    protected DSSDocument getOtherTypeDocument() {
        return new FileDocument("src/test/resources/validation/mdocIssuerSigned.cbor");
    }

    @Override
    protected DSSDocument getNoSignatureDocument() {
        return MINIMAL_DEVICE_RESPONSE;
    }

    @Override
    protected DSSDocument getXmlEvidenceRecordDocument() {
        // not applicable
        return null;
    }

    @Override
    @Test
    public void validateFromDocument() {
        List<DSSDocument> documents = getValidDocuments();
        for (DSSDocument document : documents) {
            DocumentValidator reader = DefaultAttestationDocumentValidator.fromDocument(document);
            validate(reader, true);
        }
    }

    @Override
    protected void validate(DocumentValidator validator, boolean containsSignature) {
        validator.setCertificateVerifier(new CommonCertificateVerifier());
        Reports reports = validator.validateDocument();
        assertNotNull(reports);
        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);
        assertEquals(containsSignature, simpleReport.getFirstAttestationId() != null);
    }

}
