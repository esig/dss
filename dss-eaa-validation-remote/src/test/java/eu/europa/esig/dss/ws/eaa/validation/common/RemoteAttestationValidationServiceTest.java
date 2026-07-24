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
package eu.europa.esig.dss.ws.eaa.validation.common;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.AttestationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.eaa.revocation.source.ExternalResourcesAttestationRevocationSource;
import eu.europa.esig.dss.enumerations.AttestationFormat;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.eaa.validation.dto.AttestationToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RemoteAttestationValidationServiceTest {

    private RemoteAttestationValidationService validationService;

    @BeforeEach
    void init() {
        validationService = new RemoteAttestationValidationService();
        validationService.setVerifier(new CommonCertificateVerifier());
    }

    @Test
    void test(){
        RemoteDocument attestationPresentation = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sd-jwt-eaa.json"));
        AttestationToValidateDTO dto = new AttestationToValidateDTO(attestationPresentation);
        WSReportsDTO result = validationService.validateEAA(dto);
        validateReports(result);
    }

    @Test
    void testWithRevocationSource(){
        RemoteDocument attestationPresentation = RemoteDocumentConverter.toRemoteDocument(new FileDocument("src/test/resources/sd-jwt-eaa.json"));
        AttestationToValidateDTO dto = new AttestationToValidateDTO(attestationPresentation);
        ExternalResourcesAttestationRevocationSource revocationSource = new ExternalResourcesAttestationRevocationSource(new FileDocument("src/test/resources/eaa-statuslist-jwt.json"));
        validationService.setEAARevocationSource(revocationSource);
        WSReportsDTO result = validationService.validateEAA(dto);
        Reports reports = validateReports(result);

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(1, diagnosticData.getAllEAARevocationTokens().size());
    }

    private Reports validateReports(WSReportsDTO result) {
        assertNotNull(result.getDiagnosticData());
        assertNotNull(result.getDetailedReport());
        assertNotNull(result.getSimpleReport());
        assertNotNull(result.getValidationReport());

        assertEquals(1, result.getDiagnosticData().getEAAs().size());

        assertEquals(Indication.INDETERMINATE, result.getSimpleReport().getSignatureOrTimestampOrEvidenceRecord().get(0).getIndication());

        Reports reports = new Reports(result.getDiagnosticData(), result.getDetailedReport(), result.getSimpleReport(), result.getValidationReport());

        assertNotNull(reports);
        assertNotNull(reports.getDiagnosticData());
        assertNotNull(reports.getDetailedReport());
        assertNotNull(reports.getSimpleReport());

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        AttestationWrapper eaa = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        assertNotNull(eaa);
        assertEquals(AttestationFormat.SD_JWT_VC, eaa.getEAAType());

        List<SignatureWrapper> eaaSignatures = eaa.getEAASignatures();
        assertEquals(1, eaaSignatures.size());
        SignatureWrapper signature = eaaSignatures.get(0);
        assertTrue(signature.isBLevelTechnicallyValid());

        return reports;
    }

}
