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
package eu.europa.esig.dss.cookbook.example.validate;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.TLSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.DetachedTimestampValidator;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class TimestampValidationTest extends CookbookTools {

    @Test
    public void test() {

        TSPSource goodTsa = getGoodTsa();
        TimestampBinary timestampBinary = goodTsa.getTimeStampResponse(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, "Hello World!".getBytes()));
        DSSDocument timeStampDocument = new InMemoryDocument(timestampBinary.getBytes());

        AIASource aiaSource = new DefaultAIASource();
        RevocationSource<OCSP> ocspSource = new OnlineOCSPSource();
        RevocationSource<CRL> crlSource = new OnlineCRLSource();

        // tag::demo[]
        // Configure the internet access
        CommonsDataLoader dataLoader = new CommonsDataLoader();

        // We set an instance of TrustAllStrategy to rely on the Trusted Lists content
        // instead of the JVM trust store.
        dataLoader.setTrustStrategy(TrustAllStrategy.INSTANCE);

        // Configure the TLValidationJob to load a qualification information from the corresponding LOTL/TL
        TLValidationJob tlValidationJob = new TLValidationJob();
        tlValidationJob.setOnlineDataLoader(new FileCacheDataLoader(dataLoader));

        // Configure the relevant TrustedList
        TLSource tlSource = new TLSource();
        tlSource.setUrl("http://dss-test.lu");
        tlValidationJob.setTrustedListSources(tlSource);

        // Initialize the trusted list certificate source to fill with the information extracted from TLValidationJob
        TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
        tlValidationJob.setTrustedListCertificateSource(trustedListsCertificateSource);

        // Update TLValidationJob
        tlValidationJob.onlineRefresh();

        // No we need to configure the DocumentValidator
        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setTrustedCertSources(trustedListsCertificateSource); // configured trusted list certificate source
        cv.setAIASource(aiaSource); // configured AIA Access
        cv.setOcspSource(ocspSource); // configured OCSP Access
        cv.setCrlSource(crlSource); // configured CRL Access

        // Create an instance of DetachedTimestampValidator
        DocumentValidator validator = new DetachedTimestampValidator(timeStampDocument);
        validator.setCertificateVerifier(cv);

        // Validate the time-stamp
        Reports reports = validator.validateDocument();
        SimpleReport simpleReport = reports.getSimpleReport();

        // Extract the qualification information
        TimestampQualification timestampQualification = simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId());

        // end::demo[]

        DetailedReport detailedReport = reports.getDetailedReport();
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        assertNotNull(simpleReport);
        assertNotNull(detailedReport);
        assertNotNull(diagnosticData);

    }

}
