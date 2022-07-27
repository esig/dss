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

    private static final String UA_LOTL_URI = "ua_lotl.xml";
    private static final String UA_TL_URI = "https://www.czo.gov.ua/download/tl/TL-UA.xml";

    private static TrustedListsCertificateSource trustedCertificateSource;

    @BeforeAll
    public static void init() {
        TLValidationJob tlValidationJob = new TLValidationJob();

        CommonTrustedCertificateSource lotlKeystore = new CommonTrustedCertificateSource();
        lotlKeystore.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDTjCCAjagAwIBAgIBATANBgkqhkiG9w0BAQ0FADBRMRQwEgYDVQQDDAtzZWxmLXNpZ25lZDEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMB4XDTIxMDcxMTA3MDEyOVoXDTIzMDcxMTA3MDEyOVowUTEUMBIGA1UEAwwLc2VsZi1zaWduZWQxGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALFPKQYVrMVQuvdym/ZtwT1FgpwMj680IQECLw69mJNMJcAc+E5MxIXDSpN8ar9EpmcIS1r42xsMSz0n6uiT1WRM1VBOlSbKLymp7uuA6esmWKNg1lqlyT/nG7ZdMJo5uqV/ElykFBUi3SqdA4M0Fj7sX6qPKbjRTuoVWvFuVkjKXFKk4XcJIA8Qi6hE0WYgT+D4b3ei+8f+bskF/YPlGnUKFPlu6911DxbXh8gat+Oc2oGPpLwb1OpPywn+3aavc7jRYt3YysEUChHNCBKxLj9o2S9JPZFkYp9TZ6BfltiGavI9TPqqWvLAHA+AAO9crEdRjPrCCDeEZBVZ+cU1GZUCAwEAAaMxMC8wDgYDVR0PAQH/BAQDAgZAMB0GA1UdDgQWBBSHZziIPD9aURH3lnv7nBQ2YwA8djANBgkqhkiG9w0BAQ0FAAOCAQEAlOL8AR6pmXnqRSNYg0D1tfh7KzzxkrCCXtOIkdArZFPf/9/07hYA7OlgcL466CUiKMV1LrWvibCXTtuFz0myD74nRHPE7a1T6nb6FqN8QDK/8vxAO9LCsuN1YIeI3rEPYX08Ksb0laQvW/lCFcyPqCPOgjXqCU8ERTKUrP5GKA6p+bd8AJJ8UD1GB4gC6VaK4xWEKaRAW8N8nhp+bDLlO2d4O5Fs568JOZShUQ8rqCqNX49XCG9+8MFASjPOLNC2NYHdp5tt/gKFoa9UZf+Nt3QTYsZ8Dhb/9tECAPrZrqlZVB0NjoGdS54aXyacorPfCjqrsnpys1I5iNU9aw86HQ=="));

        LOTLSource euLOTL = new LOTLSource();

        // tag::demo[]

        // Create LOTLSource supporting the trust service equivalence mapping
        LOTLSource mraEnactedLOTLSource = new LOTLSource();
        // Provide URL pointing to the LOTLSource location
        mraEnactedLOTLSource.setUrl("http://server.com/zz_lotl.xml");
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

        // NOTE : overwrite to UA values
        mraEnactedLOTLSource.setUrl(UA_LOTL_URI);
        mraEnactedLOTLSource.setTlPredicate(TLPredicateFactory.createPredicateWithCustomTSLType("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/UAlist"));

        tlValidationJob.setListOfTrustedListSources(mraEnactedLOTLSource);

        Map<String, byte[]> inMemoryMap = new HashMap<>();
        inMemoryMap.put(UA_LOTL_URI, DSSUtils.toByteArray(new FileDocument("src/test/resources/mra/lotl-ua.xml")));
        inMemoryMap.put(UA_TL_URI, DSSUtils.toByteArray(new FileDocument("src/test/resources/mra/tl-ua.xml")));
        FileCacheDataLoader fileCacheDataLoader = new FileCacheDataLoader();
        fileCacheDataLoader.setDataLoader(new MemoryDataLoader(inMemoryMap));
        fileCacheDataLoader.setCacheExpirationTime(0);

        tlValidationJob.setOfflineDataLoader(fileCacheDataLoader);

        trustedCertificateSource = new TrustedListsCertificateSource();
        tlValidationJob.setTrustedListCertificateSource(trustedCertificateSource);

        tlValidationJob.offlineRefresh();

        assertEquals(60, trustedCertificateSource.getCertificates().size());
    }

    private static Stream<Arguments> data() {
        List<Arguments> args = new ArrayList<>();
        args.add(Arguments.of(new FileDocument("src/test/resources/mra/ua-esig.asice"), SignatureQualification.ADESIG, "PKCForAdESig"));
        args.add(Arguments.of(new FileDocument("src/test/resources/mra/ua-eseal.asice"), SignatureQualification.ADESEAL, "PKCForAdESeal"));
        return args.stream();
    }

    @ParameterizedTest(name = "Signed document {index} : {0}, {1}")
    @MethodSource("data")
    public void test(DSSDocument signedDocument, SignatureQualification targetQualification, String enactedMRAName) {
        DocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        validator.setValidationTime(DSSUtils.getUtcDate(2022, 6, 11));

        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.addTrustedCertSources(trustedCertificateSource);
        validator.setCertificateVerifier(certificateVerifier);
        Reports reports = validator.validateDocument();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(targetQualification, simpleReport.getSignatureQualification(simpleReport.getFirstSignatureId()));

        List<XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(simpleReport.getFirstSignatureId());
        assertEquals(2, signatureTimestamps.size());
        for (XmlTimestamp xmlTimestamp : signatureTimestamps) {
            assertEquals(Indication.PASSED, xmlTimestamp.getIndication());
            assertEquals(TimestampQualification.TSA, xmlTimestamp.getTimestampLevel().getValue());
        }

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        assertEquals(enactedMRAName, signingCertificate.getMRAEnactedTrustServiceLegalIdentifier());
    }

}
