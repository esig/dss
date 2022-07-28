package eu.europa.esig.dss.cookbook.example.validate.mra;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureQualification;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.http.MemoryDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.tsl.function.TLPredicateFactory;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ThirdCountryLOTLTest {

    private static final String ZZ_LOTL_URI = "https://esignature.ec.europa.eu/efda/intl-pilot/api/v1/intl-pilot/tl/mra_lotl.xml";
    private static final String ZZ_TL_URI = "https://esignature.ec.europa.eu/efda/intl-pilot/api/v1/intl-pilot/tl/mra_tl_zz.xml";

    private static TrustedListsCertificateSource trustedCertificateSource;
    private static CommonTrustedCertificateSource commonTrustedCertificateSource;

    @BeforeAll
    public static void init() {
        TLValidationJob tlValidationJob = new TLValidationJob();

        CommonTrustedCertificateSource lotlKeystore = new CommonTrustedCertificateSource();
        lotlKeystore.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDZzCCAk+gAwIBAgIDB6EgMA0GCSqGSIb3DQEBCwUAMFQxFzAVBgNVBAMMDlpaLUxPVEwtc2lnbmVyMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwHhcNMTkwNzEzMDkwMzEwWhcNMjUwNzEzMDkwMzEwWjBUMRcwFQYDVQQDDA5aWi1MT1RMLXNpZ25lcjEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjtkwfK8NplyrRD2Kd6SUe7Va7dQGiN2fN/U6jO/GqvA8s0Yvof9iNAftZPQfJYBzMGPYsZ8IPCjoWGCfhH2DWglqyUBSKJuB1TAZOpXmdYBRMq25/1AmSx9E4ICoQdIUDFqNiQdLf/YGOqdOAts2aNUnTL05VGchuWPUmotpSyvy01FsPyQRz00mD/ZM1Dpd1pge1s5QsaPKQNLLTVje5zJMqqWzvdugKOp7S4jCm3WVAMelbVwnWGPFfCOVj+Hd8Lq5tqXJbkNnVobmL5hdknXH976gNysXScHikcF06TBUWWrsbMBiK04KIteIszXGeqb7jNMl8Te9If6ZE2GyPwIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCBsAwHQYDVR0OBBYEFKcw5AM8mryNt4vmGj61AJG/9QI+MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAILwc5+cjyOgxJVzJhjEzbR7pYJKvqXgNU/eQeNdZ1zWqbVv0fJ0XzcvDobVu5MWj/oK1P1Ng9jGofE9+4XkXNdme98yiCPr1wO4l6u3g4a3WWAH9QWza42zOBBlSwT5yELUMWHUBVN17DSgnEOQ9hifhhy/fM7AlYYtUl3RXW13qkWmG83KK12FX6qDBxkKfhJ5v2xM0sZnEs906NVshVHcOiI/HIxi5V83aDLxBNVthHvlu0oDop0z5yuEuPOyFEOZbvoJBVCKpMcqvGM8lQ29cWxuQSmnNDO3fcVFpmEWXi4UUa6WXgl/YamdoMPgUDh8w4U5/FyZSpGbYdKSAJY="));

        LOTLSource euLOTL = new LOTLSource();

        // tag::demo[]

        // Create LOTLSource supporting the trust service equivalence mapping
        LOTLSource mraEnactedLOTLSource = new LOTLSource();
        // Provide URL pointing to the LOTLSource location
        mraEnactedLOTLSource.setUrl(ZZ_LOTL_URI);
        // Set MRA Support in order to enable trust service equivalence mapping support
        mraEnactedLOTLSource.setMraSupport(true);
        // Provide keystore containing the certificate used to sign the LOTL
        mraEnactedLOTLSource.setCertificateSource(lotlKeystore);
        // Specify filter of Trusted Lists by the corresponding TSLType defined within the LOTL
        // NOTE : by default "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric" TSLType is used
        mraEnactedLOTLSource.setTlPredicate(TLPredicateFactory.createPredicateWithCustomTSLType("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/ZZlist"));

        // Provide the LOTL to the TLValidationJob (may be used alone or with other LOTL/TLs, e.g. with EU LOTL)
        tlValidationJob.setListOfTrustedListSources(euLOTL, mraEnactedLOTLSource);

        // end::demo[]

        tlValidationJob.setListOfTrustedListSources(mraEnactedLOTLSource);

        Map<String, byte[]> inMemoryMap = new HashMap<>();
        inMemoryMap.put(ZZ_LOTL_URI, DSSUtils.toByteArray(new FileDocument("src/test/resources/mra/mra-lotl.xml")));
        inMemoryMap.put(ZZ_TL_URI, DSSUtils.toByteArray(new FileDocument("src/test/resources/mra/mra-zz-tl.xml")));
        FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
        fileCacheDataLoader.setDataLoader(new MemoryDataLoader(inMemoryMap));
        fileCacheDataLoader.setCacheExpirationTime(0);

        tlValidationJob.setOfflineDataLoader(fileCacheDataLoader);

        trustedCertificateSource = new TrustedListsCertificateSource();

        tlValidationJob.setTrustedListCertificateSource(trustedCertificateSource);

        tlValidationJob.offlineRefresh();

        assertEquals(1, trustedCertificateSource.getCertificates().size());

        // load additional trusted certificates
        commonTrustedCertificateSource = new CommonTrustedCertificateSource();
        commonTrustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIEdjCCA16gAwIBAgIDAYcOMA0GCSqGSIb3DQEBCwUAMH8xIzAhBgNVBAMMGlRlc3QtUVRTUC0xLVJvb3RDQS1mcm9tLVpaMTgwNgYDVQQKDC9UZXN0IFF1YWxpZmllZCBUcnVzdCBTZXJ2aWNlIFByb3ZpZGVyIDEgZnJvbSBaWjERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAlpaMB4XDTIxMDgxMzA5MDMwOFoXDTIzMDYxMzA5MDMwOFowfzEjMCEGA1UEAwwaVGVzdC1RdWFsaWZpZWQtQ0ExLWZyb20tWloxODA2BgNVBAoML1Rlc3QgUXVhbGlmaWVkIFRydXN0IFNlcnZpY2UgUHJvdmlkZXIgMSBmcm9tIFpaMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCWlowggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrzDrYvG2xE3M6aJAyyrEeV2gScxu835EPxLyKBV4M+vQTWaIvhtcF6Rf4nILVu9yE0MULFHagjMZiR9XlfVmlZKb6TSKeE9jTd/qBd2e3m8DX+lZvkrgWbM2qT290Jq41pzGjuzGjEpFxq3UY6tWYfw5Pw1wh7Cw6IrLU3ooIGk8gpiR5X0EvghTThiY46cnp+TsRXRNTq9Wfw8e1e7iPzqv4+FSM9IssJ0xHog0Gvp2EhzTbWWIKXExHtZP3j4yJtSJ14PcZ2/YqYqGOR8M/HAeHoW9be2qqWBVVu+R8NckjhRoYYHjhqjcAcNvzXqXU1CDu7CryKyV4Nlx0mRw1AgMBAAGjgfowgfcwDgYDVR0PAQH/BAQDAgEGMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly9kc3Mubm93aW5hLmx1L3BraS1mYWN0b3J5L2NybC9UZXN0LVFUU1AtMS1Sb290Q0EtZnJvbS1aWi5jcmwwXwYIKwYBBQUHAQEEUzBRME8GCCsGAQUFBzAChkNodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvVGVzdC1RVFNQLTEtUm9vdENBLWZyb20tWlouY3J0MB0GA1UdDgQWBBTbNZzMrr+fJb3OjhwGi/ytBxy49TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA9bIpdRlF56Q4T1TBchIE2QNYDo7Dnng9zrXH/mL3eT8TQt3VGjECNoygKhlX1yLICjfdfMcYvnsKEg73k5PGllvf0rULdZ7Zp6pEMZ+ktRrktnIT+64pCxk7piwUY+mHdyfYdnRoaYqQkCyTXUz4DlaNymHUZwmF/TBq1pfm5fefc6QEV8LD/zal1QEsT4HFTyr6eAGzwMfZ/PIC0p1ixlqGQ1987uuFWtb72PYStcG48jhoHeel7UwTowGt360M3jSVgoaXqdYHyZ0S1KXAJw2YaDcQBoAmXMywqE1dEzuvTJ+qBRKeNaQp51wWCpHprNst3ncCPF4BQO0xNi8r+"));
        commonTrustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIEXTCCA0WgAwIBAgIDAYcEMA0GCSqGSIb3DQEBCwUAMGIxJTAjBgNVBAMMHFRlc3QtTmF0aW9uYWwtUm9vdENBLWZyb20tWloxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTAeFw0yMTA4MTMwOTAzMDhaFw0yMzA2MTMwOTAzMDhaMH8xIzAhBgNVBAMMGlRlc3QtUVRTUC0xLVJvb3RDQS1mcm9tLVpaMTgwNgYDVQQKDC9UZXN0IFF1YWxpZmllZCBUcnVzdCBTZXJ2aWNlIFByb3ZpZGVyIDEgZnJvbSBaWjERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAlpaMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoPsg9dIteInHtpLtHqpqcxbYFJZe1w0Fe+xrGOsOvd12gcnsoRcXFi+Lv7o/e0oyu2BWoffXLpKkNnLCDHCrajhc9ShiJ4zHPdHv+q4l5FbZNvi31oerSAgfFZM2VNh9B3EHrNT41U0X52mDw5lkKitP+X155bvMmRXblXg+fOS/PRh3ECAN2JgQmNRny4YmwUGqLhQMFCp8rlfft5yG4wof36jFhD9BL9Ywr79He6EEHNoeUBPNBQzMWfN3gRrn5vzpeuYLOar5NPuenuMlJwkMV6UNJDUBa1qkIZKKLieZ2RkEeSAf8N62xw3izMdM8/G3XE+qHoI451xVJ5zz9QIDAQABo4H+MIH7MA4GA1UdDwEB/wQEAwIBBjBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcmwvVGVzdC1OYXRpb25hbC1Sb290Q0EtZnJvbS1aWi5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vZHNzLm5vd2luYS5sdS9wa2ktZmFjdG9yeS9jcnQvVGVzdC1OYXRpb25hbC1Sb290Q0EtZnJvbS1aWi5jcnQwHQYDVR0OBBYEFD0wYpBbpyaPwYJi5X+tClLOw24RMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJAn8STlGwBckv3mLVeVctM2ozF5O/QG5KIxXnUzWUEue2erUtPS9W13qkJBbiOgYYzEeQJGk7OYL47XN7D3FneazlidEfqsoo1n2FAqiwdlZ+MKIxsA0v9aoNJb++Knb4df1xNPNOQp7ugWUuyIvOUz5PtKyVDNn5vv3L1W44k4NP2KrF60NCERAwjfzl9mAALUwYWJ/9isQBjy5HhAFkQUo33grCWGH9ha8UMFfza2whyydCRkPUEFA4R/KNRqjh5QSZdDnqdPNb8KujQYlNIemGJKZyH472WqyBYElW8wPpU+KCtWS6x4FWrrFVp90Z3x0boBUvxM39rZ0Hu1hZA="));
        commonTrustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIID0jCCArqgAwIBAgIDAw1BMA0GCSqGSIb3DQEBCwUAMH8xIzAhBgNVBAMMGlRlc3QtUVRTUC0xLVJvb3RDQS1mcm9tLVpaMTgwNgYDVQQKDC9UZXN0IFF1YWxpZmllZCBUcnVzdCBTZXJ2aWNlIFByb3ZpZGVyIDEgZnJvbSBaWjERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAlpaMB4XDTIxMDgxMzA5MDMwOFoXDTIzMDYxMzA5MDMwOFowfDEgMB4GA1UEAwwXWlotUVRTUDEtb2NzcC1yZXNwb25kZXIxODA2BgNVBAoML1Rlc3QgUXVhbGlmaWVkIFRydXN0IFNlcnZpY2UgUHJvdmlkZXIgMSBmcm9tIFpaMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCWlowggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8p9nCkMQllgKNuWqLGzSjZr+MRxmPmakEhW2cwfXpC6EmLyikyXiW1Z60iZiXRAIpOHkvcl1t5fhxfCtlJhN6RVpzjS7zT3yHG93UDaHP7lMXshjCyJr6WbZaNwKJkf8swbaHrYkH97fdWl/RhcJ2WAZIgbUjw8X80C1xUj2zgy4roIkx/7MKHjJyu4xpGfeFS5OcYz5+0F9oUnck++jOysYVBCdkXy8dnFM9I4CzIDe7m3iKNmvBR7NB9EvQP+0iDTdfvnfyKCeIaqeaOZWNPQ0kEDx2e2VH7SHC9i+/BISSrhb9OeZ4ese+spANgs0mn7hD4BS/W72NS7ZrV/JTAgMBAAGjWjBYMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCTAdBgNVHQ4EFgQU35hvjwMRRr2lbo0lDCH6CH/XVqYwDwYJKwYBBQUHMAEFBAIFADANBgkqhkiG9w0BAQsFAAOCAQEAN6hQ9HD9z0Cc/OeAkYWWuSNtf0rKfMiHyKdT9OrCR8La/r90UVM6pb09+kKYoRQqpvQrWk03K9X0eeFi9XVVk0Cp/8vNHDgO9Tnj0wvXLMc592Mo+LdmB0uUpj3Lz7Bz00Q07uUVIAmrhpRxH7L6bA4eOqRTruKiO9bVcE8vACKBCkDEXoADpbBO2Y6zWhXtmqrAaSzgLS5DKUgywZvuB2FMvSko7gro00UsYW5rp0KHys7pHZ9VxltNb+KFWyr9G892IzaSyVV1uGMWh8RjOZy1ZBUO//XZQ8JAl225FhW5pQv6BDtRUVEU+tnEds1WfYmczqvLGT6h/H4jgFN6Yg=="));
        commonTrustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIID8zCCAtugAwIBAgICAfQwDQYJKoZIhvcNAQELBQAwTTEQMA4GA1UEAwwHcm9vdC1jYTEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMB4XDTIxMDgxMzA5MDMyMFoXDTIzMDYxMzA5MDMyMFowTjERMA8GA1UEAwwIZ29vZC10c2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL04iODk3WfuMlW0SqV3zq5hObYtaoRhvqhIOeEvhTTrXam/8F2FI4FYh9d3/XSL77wMoIJET/bPqsXSY8HLMYZCCEAloJtMwdojHe99D+ZdDvUpf2rU8PHcCKe/8e+oPolVPnZtlQTtludRGPnxa+YgIbKV8gX8uqbswJAAPJ5HMps5MCtOKBk1fZpt3h2uEb1y6bBmFn9EuSF6907rl10ufbBDlHyt3hTAKAKRTBbsQfqoJBBPDlxk5HQokEfORIuss/Ke2Ym2p8jurxFzh8IpCt8ltgAFIvbw7Oiw052qK6eYndturp7v/Dc0B54m4pUWfexWyOJZTnDYsxzBntUCAwEAAaOB2zCB2DAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3JsL3Jvb3QtY2EuY3JsMEwGCCsGAQUFBwEBBEAwPjA8BggrBgEFBQcwAoYwaHR0cDovL2Rzcy5ub3dpbmEubHUvcGtpLWZhY3RvcnkvY3J0L3Jvb3QtY2EuY3J0MB0GA1UdDgQWBBRfvqy/D0Ff15pypH45tzI8aiMSWTANBgkqhkiG9w0BAQsFAAOCAQEAIfFoY8rQeDQUsignDm1kNfaDMkwVohMK/pV+3MvpITvXl3ii+FSHp075M2ZKYtG+rB4fdPmZOYRBx7pxmzmnYP2xBTGPNvzoOl/x/mZWSgKXUbMzhHWWwL2lQvgpDlkKaOZC6Qtgh7OyAUET3vLOKaiBQ8XUsBe+y7L5t3tHsurPQMWMGl9a5RQ3HOWO95QRG1XK1gSxSar66lUE3shyDtI/1KoJsm49MQTJDLmsLVy8r7g/uTTfgZuao7CWiZNXthZErqp6JyXUPrYkt2NFEBPNVH3mGAzBbszbugM+uzzemOm+Eit3suVbISeibvFlk+1punO2hyVar/Utnq7EUw=="));
    }

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();
        args.add(Arguments.of(new FileDocument("src/test/resources/mra/john-doe-lta.xml"), SignatureQualification.QESIG, "QCForESig"));
        args.add(Arguments.of(new FileDocument("src/test/resources/mra/john-doe-lta.pdf"), SignatureQualification.QESIG, "QCForESig"));
        return args.stream();
    }

    @ParameterizedTest(name = "Signed document {index} : {0}, {1}")
    @MethodSource("data")
    public void test(DSSDocument signedDocument, SignatureQualification targetQualification, String enactedMRAName) {
        DocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setValidationTime(DSSUtils.getUtcDate(2022, 6, 11));

        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.addTrustedCertSources(trustedCertificateSource, commonTrustedCertificateSource);
        validator.setCertificateVerifier(certificateVerifier);
        Reports reports = validator.validateDocument();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(targetQualification, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        List<XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(2, signatureTimestamps.size());
        for (XmlTimestamp xmlTimestamp : signatureTimestamps) {
            assertEquals(Indication.PASSED, xmlTimestamp.getIndication());
            assertEquals(TimestampQualification.NA, xmlTimestamp.getTimestampLevel().getValue());
        }

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        assertEquals(enactedMRAName, signingCertificate.getMRAEnactedTrustServiceLegalIdentifier());
    }

}
