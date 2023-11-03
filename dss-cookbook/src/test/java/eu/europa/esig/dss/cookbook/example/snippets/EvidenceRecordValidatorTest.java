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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class EvidenceRecordValidatorTest {

    @Test
    public void test() throws Exception {
        // tag::evidence-record-alone[]
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.dss.model.FileDocument;
        // import eu.europa.esig.dss.validation.CertificateVerifier;
        // import eu.europa.esig.dss.validation.CommonCertificateVerifier;
        // import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;
        // import eu.europa.esig.dss.validation.reports.Reports;

        // Load evidence record document to be validated
        DSSDocument evidenceRecordDocument = new FileDocument("src/test/resources/snippets/evidence-record.xml");

        // The method allows instantiation of a related evidence record validator for a provided document
        // independently on its format (the target evidence record validation module must be added as dependency)
        EvidenceRecordValidator evidenceRecordValidator = EvidenceRecordValidator.fromDocument(evidenceRecordDocument);

        // Create a CertificateVerifies containing validation process configuration
        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        // configure the CertificateVerifier as needed

        // Provide the CertificateVerifier to the document validator
        evidenceRecordValidator.setCertificateVerifier(certificateVerifier);

        // Load the archive data object(s) covered by the evidence record as a detached content
        DSSDocument archiveDataObject = new FileDocument("src/test/resources/snippets/archive-data-object.xml");
        evidenceRecordValidator.setDetachedContents(Collections.singletonList(archiveDataObject));

        // Validate the evidence record
        Reports reports = evidenceRecordValidator.validateDocument();
        // end::evidence-record-alone[]

        assertNotNull(reports);
        assertNotNull(reports.getDiagnosticData());
        assertNotNull(reports.getSimpleReport());
        assertNotNull(reports.getDetailedReportJaxb());
        assertNotNull(reports.getEtsiValidationReportJaxb());

        // tag::evidence-record-signed-doc-validator[]
        // import eu.europa.esig.dss.validation.DocumentValidator;
        // import eu.europa.esig.dss.validation.SignedDocumentValidator;

        // Validate an evidence record using a common SignedDocumentValidator class
        DocumentValidator documentValidator = SignedDocumentValidator.fromDocument(evidenceRecordDocument);
        // end::evidence-record-signed-doc-validator[]

        documentValidator.setCertificateVerifier(new CommonCertificateVerifier());

        reports = documentValidator.validateDocument();

        assertNotNull(reports);
        assertNotNull(reports.getDiagnosticData());
        assertNotNull(reports.getSimpleReport());
        assertNotNull(reports.getDetailedReportJaxb());
        assertNotNull(reports.getEtsiValidationReportJaxb());
    }

}
