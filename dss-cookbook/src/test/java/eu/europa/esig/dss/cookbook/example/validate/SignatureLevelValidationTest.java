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
package eu.europa.esig.dss.cookbook.example.validate;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SignatureLevelValidationTest {

    @Test
    public void validateXAdESBLevel() throws Exception {

        // See Trusted Lists loading
        CertificateSource keystoreCertSource = new KeyStoreCertificateSource(new File("src/test/resources/self-signed-tsa.p12"), "PKCS12", "ks-password");
        CertificateSource adjunctCertSource = new KeyStoreCertificateSource(new File("src/test/resources/self-signed-tsa.p12"), "PKCS12", "ks-password");

        // Create an instance of a trusted certificate source
        CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
        trustedCertSource.importAsTrusted(keystoreCertSource);

        // tag::demo[]
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.dss.model.FileDocument;
        // import eu.europa.esig.dss.service.crl.OnlineCRLSource;
        // import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
        // import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
        // import eu.europa.esig.dss.validation.CertificateVerifier;
        // import eu.europa.esig.dss.validation.CommonCertificateVerifier;
        // import eu.europa.esig.dss.validation.SignedDocumentValidator;
        // import eu.europa.esig.dss.validation.executor.ValidationLevel;
        // import eu.europa.esig.dss.validation.reports.Reports;
        // import java.io.File;

        // The document to be validated (any kind of signature file)
        DSSDocument document = new FileDocument(new File("src/test/resources/signature-pool/signedXmlXadesLT.xml"));

        // First, we need a Certificate verifier
        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setAIASource(new DefaultAIASource());
        cv.setOcspSource(new OnlineOCSPSource());
        cv.setCrlSource(new OnlineCRLSource());

        cv.addTrustedCertSources(trustedCertSource);
        cv.addAdjunctCertSources(adjunctCertSource);

        // We create an instance of DocumentValidator
        // It will automatically select the supported validator from the classpath
        SignedDocumentValidator documentValidator = SignedDocumentValidator.fromDocument(document);

        // We add the certificate verifier
        documentValidator.setCertificateVerifier(cv);

        // Validate the signature only against its B-level
        documentValidator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);

        // Here, everything is ready. We can execute the validation (for the example, we use the default and embedded
        // validation policy)
        Reports reports = documentValidator.validateDocument();

        // end::demo[]

        // We have 3 reports
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        DetailedReport detailedReport = reports.getDetailedReport();
        SimpleReport simpleReport = reports.getSimpleReport();

        assertNotNull(reports);
        assertNotNull(diagnosticData);
        assertNotNull(detailedReport);
        assertNotNull(simpleReport);

        // tag::demo-ltv[]
        // import eu.europa.esig.dss.validation.SignedDocumentValidator;
        // import eu.europa.esig.dss.validation.executor.ValidationLevel;

        documentValidator = SignedDocumentValidator.fromDocument(document);
        // configure

        // Validate the signature with long-term validation material
        documentValidator.setValidationLevel(ValidationLevel.LONG_TERM_DATA);
        // end::demo-ltv[]

        // tag::demo-lta[]
        // import eu.europa.esig.dss.validation.SignedDocumentValidator;
        // import eu.europa.esig.dss.validation.executor.ValidationLevel;

        documentValidator = SignedDocumentValidator.fromDocument(document);
        // configure

        // Validate the signature with long-term availability and integrity material
        documentValidator.setValidationLevel(ValidationLevel.ARCHIVAL_DATA);
        // end::demo-lta[]
    }

}
