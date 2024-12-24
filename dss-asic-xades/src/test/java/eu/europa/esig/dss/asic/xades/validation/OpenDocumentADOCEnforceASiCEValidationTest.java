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
package eu.europa.esig.dss.asic.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.Calendar;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OpenDocumentADOCEnforceASiCEValidationTest extends AbstractASiCWithXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        DSSDocument document = new FileDocument("src/test/resources/validation/container-signed.adoc");
        document.setMimeType(MimeTypeEnum.ASICE);
        return document;
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator documentValidator = super.getValidator(signedDocument);
        documentValidator.setValidationTime(DSSUtils.getUtcDate(2024, Calendar.JANUARY, 1));
        return documentValidator;
    }

    @Override
    protected CertificateSource getTrustedCertificateSource() {
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDVzCCAj+gAwIBAgIBATANBgkqhkiG9w0BAQ0FADBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMjIxMTAyMTIxMTQ0WhcNMjQxMTAyMTIxMTQ0WjBNMRAwDgYDVQQDDAdyb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDSUwTRaKkCgEvwPh+atSrFrdEouMsLUdNNlSVgDooLIB51cgi5kJzh/eMK9pO+aZ5BEnI1CfsutuM0AuTAbuf70k3geyAUdBl8ue9KrexH5Nh4J5i1DwwVHNCA1qpYOJNrjWdyIyPuDmnyAw/OsKBcp79a4NZogH3B9a+5pTZhyu8UHy8YvI8J1RqO6EB9w1JwjROVPSJ9b6EtGhqV8nUOmIEZV6tHjqKLdUysQhicydpOi6llVku1UdWNf9cryYV+dL6hcp+bPVnG1pPPxqelFwred/n7BxjiiPE3G40bLABzc78kNTx4khe8/y536bQt5yaSn0EO/aBU6sofDo6ZAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQU1o/+XFNMQfOtajgRQ9pi7rqkMXAwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAe+C0dnUVe6NCHh51Z2utDMnviUrPVcYV9ZrQeSU3WyOkvCorHpkubNu2Fkkuuj1gRyVWujMyddJq3cY2cMjUjL+KhcNkzDbECk1WBEAQGxC7Jjx7sK83xIej6rTdAdePjwgAR9Yhza0oHyBHWBsLvrcRKSl1fvRGjot1uOgPjKzk0SFZhjC87Eg8kcoDNsmBTNObB6m5lW4pkK9AcaVVDucgyO3Q+k73F4il+nW1ySMbYsdfzRFtzqkb372ieTxCSoAeQHOGjojM4xF7OVl4a6MqepGEj2dlBrwje9Wf9sQbc0OCjLaAUzS8x32L6YqHOycx2eatDxwzjePPUmCgsQ=="));
        return trustedCertificateSource;
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        super.checkContainerInfo(diagnosticData);

        assertEquals(ASiCContainerType.ASiC_E, diagnosticData.getContainerType());
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId())));
        assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())));
        List<String> warningMessageKeys = simpleReport.getAdESValidationWarnings(simpleReport.getFirstSignatureId())
                .stream().map(Message::getKey).collect(Collectors.toList());
        assertTrue(warningMessageKeys.contains(MessageTag.BBB_FC_IEMCF_ANS.getId())); // unknown container type (not ASiC-S, nor ASiC-E)
        assertTrue(warningMessageKeys.contains(MessageTag.BBB_CV_IAFS_ANS.getId())); // not all files signed (metadata folder)
        assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationInfo(simpleReport.getFirstSignatureId())));
    }

}
