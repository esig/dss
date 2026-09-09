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

class MdocIssuerSignedDocumentValidatorTest extends AbstractTestDocumentValidator {

    private static final DSSDocument MINIMAL_ISSUER_SIGNED = buildMinimalIssuerSigned();

    private static DSSDocument buildMinimalIssuerSigned() {
        CBORValue issuerSigned = CBOR.map()
                .put("issuerAuth", buildCoseSign1())
                .value();
        return new InMemoryDocument(CBORUtils.serializeCbor(issuerSigned));
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

    @Test
    void test() {
        MdocIssuerSignedDocumentValidator validator = new MdocIssuerSignedDocumentValidator();

        DSSDocument mdoc = MINIMAL_ISSUER_SIGNED;
        assertTrue(validator.isSupported(mdoc));

        CBORValue nameSpacesOnly = CBOR.map()
                .put("nameSpaces", CBOR.map().value())
                .value();
        mdoc = new InMemoryDocument(CBORUtils.serializeCbor(nameSpacesOnly));
        assertTrue(validator.isSupported(mdoc));

        CBORValue bothKeys = CBOR.map()
                .put("nameSpaces", CBOR.map().value())
                .put("issuerAuth", buildCoseSign1())
                .value();
        mdoc = new InMemoryDocument(CBORUtils.serializeCbor(bothKeys));
        assertTrue(validator.isSupported(mdoc));

        mdoc = new FileDocument("src/test/resources/validation/mdocIssuerSigned.cbor");
        assertTrue(validator.isSupported(mdoc));

        CBORValue wrongKeyMap = CBOR.map()
                .put("test", 1)
                .value();
        DSSDocument wrong = new InMemoryDocument(CBORUtils.serializeCbor(wrongKeyMap));
        assertFalse(validator.isSupported(wrong));
        wrong = new FileDocument("src/test/resources/validation/mdocRefImpl.mdoc");
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
        return new MdocIssuerSignedDocumentValidator();
    }

    @Override
    protected SignedDocumentValidator initValidator(DSSDocument document) {
        return new MdocIssuerSignedDocumentValidator(document);
    }

    @Override
    protected List<DSSDocument> getValidDocuments() {
        return Collections.singletonList(new FileDocument("src/test/resources/validation/mdocIssuerSigned.cbor"));
    }

    @Override
    protected DSSDocument getMalformedDocument() {
        return new InMemoryDocument(CBORUtils.serializeCbor(CBOR.array().value()));
    }

    @Override
    protected DSSDocument getOtherTypeDocument() {
        return new FileDocument("src/test/resources/validation/mdocRefImpl.mdoc");
    }

    @Override
    protected DSSDocument getNoSignatureDocument() {
        // not applicable
        return null;
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
