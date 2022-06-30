package eu.europa.esig.dss.cookbook.example.validate;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.tsl.function.TypeOtherTSLPointer;
import eu.europa.esig.dss.tsl.function.XMLOtherTSLPointer;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MRATest extends PKIFactoryAccess {

    @Test
    public void test() {
        // prepare TLValidationJob
        TLValidationJob tlValidationJob = new TLValidationJob();

        TrustedListsCertificateSource trustedListsCertificateSource = new TrustedListsCertificateSource();
        tlValidationJob.setTrustedListCertificateSource(trustedListsCertificateSource);

        FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
        Map<String, byte[]> documentMap = new HashMap<>();
        documentMap.put("https://esignature.ec.europa.eu/efda/intl-pilot/api/v1/intl-pilot/mra_lotl.xml",
                DSSUtils.toByteArray(new FileDocument("src/main/resources/mra_lotl.xml")));
        documentMap.put("https://esignature.ec.europa.eu/efda/intl-pilot/api/v1/intl-pilot/tl/mra_tl_zz.xml",
                DSSUtils.toByteArray(new FileDocument("src/main/resources/mra_tl_zz.xml")));
        MemoryDataLoader memoryDataLoader = new MemoryDataLoader(documentMap);
        fileCacheDataLoader.setDataLoader(memoryDataLoader);
        fileCacheDataLoader.setCacheExpirationTime(0);
        tlValidationJob.setOfflineDataLoader(fileCacheDataLoader);

        LOTLSource lotlSource = new LOTLSource();
        lotlSource.setUrl("https://esignature.ec.europa.eu/efda/intl-pilot/api/v1/intl-pilot/mra_lotl.xml");
        CommonTrustedCertificateSource lotlCertificateSource = new CommonTrustedCertificateSource();
        lotlCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIID2DCCAsCgAwIBAgIUDe6bB81ZFSUUNiO9ZKQCwRkmpmgwDQYJKoZIhvcNAQELBQAwfzELMAkGA1UEBhMCQkUxETAPBgNVBAgMCEJydXNzZWxzMREwDwYDVQQHDAhCcnVzc2VsczEcMBoGA1UECgwTRXVyb3BlYW4gQ29tbWlzc2lvbjEUMBIGA1UECwwLVEVTVCBMT1RMU08xFjAUBgNVBAMMDUxPVEwgc2lnbmVyIDEwHhcNMjAwNDE3MTUwOTA2WhcNMzAwNDE1MTUwOTA2WjB/MQswCQYDVQQGEwJCRTERMA8GA1UECAwIQnJ1c3NlbHMxETAPBgNVBAcMCEJydXNzZWxzMRwwGgYDVQQKDBNFdXJvcGVhbiBDb21taXNzaW9uMRQwEgYDVQQLDAtURVNUIExPVExTTzEWMBQGA1UEAwwNTE9UTCBzaWduZXIgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALxkc0O+OK3cqyB5tZTbkiCozuW7n1AUDNtfupm+LHouaCyZ68UKo4ipQWAMkb3Ln5QbYnE3ZdOcexCF8EmiofNf5OH9CLBILoZ6n2+B8TyFMOclbJBtXfALFvGuA13xx68xMLLklIF/qRF2sYTL3Y1UW19sBvRWM0wMe6aCwRN05F09+MDdXaPzbtmmxIKZtWnyTuP9CidUEUK5iP26TuN1MiFP7Sut3OtNG/UnGf4J93aO0vW+NBu+RS2DR+P/iQlZyw4zRxNJPUfC/opH2Bboq1/1Haz402O5ERjmD/AcY/GpxJsrHFQ6E5fwAcSUyGntD6a7v1NspDODryHQAkECAwEAAaNMMEowCQYDVR0TBAIwADALBgNVHQ8EBAMCB4AwEQYDVR0lBAowCAYGBACRNwMAMB0GA1UdDgQWBBR3byLb7hXeikZAOX0l6SEAhTsQDDANBgkqhkiG9w0BAQsFAAOCAQEAny7iU/UfZqkzm6EtslwzBxo2APtwxemtMFaXACUs82OfompGD9TnD2UI9eMQzI1vdSXvm+nQ/wODaJA7qpiQ/uveL/jdxfkogLLvK6V2j5mQN7A/oOmOZpPbOQJoS8h+/2M6bihCawz9v5VnEqmnjmdv8bkDRQCDdvcE5A2eblMsKcEO9RXEVUzXRsFzVYBf2LQeWDKb66GxxSTApQkHCeNZKoEBtEF3AJRf4rZDQ3cKcEnl4aXi//V3Dgqyg5Wa1vKlRUlzWsrkN8RbPYVTmyZR4/Xsu8TY1hy5fWBMMq8rVSVjp26t//ZhV24ZluzT//dxA5zksRj+iTeBH1EZ/Q=="));
        lotlSource.setCertificateSource(lotlCertificateSource);
        lotlSource.setTlPredicate(new XMLOtherTSLPointer().and(new TypeOtherTSLPointer("http://example/TSLType/CCgeneric")));
        tlValidationJob.setListOfTrustedListSources(lotlSource);

        tlValidationJob.offlineRefresh();

        // validate document
        DSSDocument documentToVerify = new FileDocument("src/main/resources/sample_document_mra.pdf");
        DocumentValidator documentValidator = SignedDocumentValidator.fromDocument(documentToVerify);
        CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
        completeCertificateVerifier.addTrustedCertSources(trustedListsCertificateSource);
        documentValidator.setCertificateVerifier(completeCertificateVerifier);

        Reports reports = documentValidator.validateDocument();
        SimpleReport simpleReport = reports.getSimpleReport();

        List<String> signatureIdList = simpleReport.getSignatureIdList();
        assertEquals(2, signatureIdList.size());

        boolean tlSigFound = false;
        boolean thirdCountrySigFound = false;
        for (String sigId : signatureIdList) {
            if (Indication.TOTAL_PASSED.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SignatureQualification.ADESIG, simpleReport.getSignatureQualification(sigId));
                thirdCountrySigFound = true;
            } else if (Indication.INDETERMINATE.equals(simpleReport.getIndication(sigId))) {
                assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, simpleReport.getSubIndication(sigId));
                tlSigFound = true;
            }
        }
        assertTrue(tlSigFound);
        assertTrue(thirdCountrySigFound);
    }

    @Override
    protected String getSigningAlias() {
        return SELF_SIGNED_USER;
    }

}
