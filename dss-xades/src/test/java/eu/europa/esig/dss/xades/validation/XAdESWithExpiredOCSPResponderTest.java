package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESWithExpiredOCSPResponderTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument(new File("src/test/resources/validation/xades-lt-with-expired-ocsp-responder.xml"));
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDbDCCAlSgAwIBAgICA+gwDQYJKoZIhvcNAQENBQAwVzEaMBgGA1UEAwwRb2NzcC1za2lwLXJvb3QtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTAeFw0yMDAyMDQwODQwNDNaFw0yMjAyMDQwODQwNDNaMFcxGjAYBgNVBAMMEW9jc3Atc2tpcC1yb290LWNhMRkwFwYDVQQKDBBOb3dpbmEgU29sdXRpb25zMREwDwYDVQQLDAhQS0ktVEVTVDELMAkGA1UEBhMCTFUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6ppYmjJrDqTApaXkIvi4wrvCgBZYTkPVun4kFEKREkkMwX9s2uCEQred9bymJH3yXZ0flr1vvWqG+W4ySZTYuJToL0WK8cy310wCQiBeSxg/P3k8k6aP89cEqyogrRp7ZlfA6j6sFDeMEQYCHXELFoaAmsKJd8I0iByi8b4JM2aPmuM277dfwLaTMih0IzXR/dpVUwIVv+s66+T0YKqknfbU4CixAI5GH8fIG8xyJK4fuRBH2Acvy5VIf9R39mPaX0kZcRc9uC8wg59fqaDxGaheXtIOVex8RpeDdjZmyEsfrzoI0IJUQ8C6hDgp+3QEmVmCVloByusWt4w61P7upAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUSwrZMrY1qyUlGJfW8wegv0Hdt2wwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOCAQEAJeIrKbdRVeIm1+ONp3oVlarjNIRf2k56h6NK8LkvKi1uftZz9uHQCftMSD3infFXzcnhNyZFRN8sdLYm5XorBUh7dIGVGcVVoP6oylNXWRtU1PZehPkKdklYgyw7ammWvaZmOnh6G9mmah6JfO9UqWT2YzdJ+2Ww3jXaBN/6oGgQ1HFu8gwDXu9NybA8tiqC/B2Y43HHCyGNLpKGGD76w4YWWekxH0wablxdaWEr3RdwVt8kKuflDeTbvwqIclqfrR0u4JjDVFjNIIy3qqi51LoSbkCB1bOWNjrDiFR6rzC5irDBVULPfj7q9HVD1m0PnZtJOl+7BgvyqT/brniylQ=="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIEFjCCAv6gAwIBAgICA+wwDQYJKoZIhvcNAQELBQAwVzEaMBgGA1UEAwwRb2NzcC1za2lwLXJvb3QtY2ExGTAXBgNVBAoMEE5vd2luYSBTb2x1dGlvbnMxETAPBgNVBAsMCFBLSS1URVNUMQswCQYDVQQGEwJMVTAeFw0xODAyMDQwODQwNDNaFw0yNDAyMDQwODQwNDNaMFgxGzAZBgNVBAMMEm9jc3Atc2tpcC12YWxpZC1jYTEZMBcGA1UECgwQTm93aW5hIFNvbHV0aW9uczERMA8GA1UECwwIUEtJLVRFU1QxCzAJBgNVBAYTAkxVMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtA4d+plmLqU8+Hr4pMJfN2hgChMf5vlXJ/WBYemS0o5UIp7K9ug0vWA7Kmv4smCktWm+9NDXlsyF7inKAPFmBBObn8TWF+N72ZmV+M/ddP7cUuAFmsFCBPbuihcFdw3xhcMyS30DlkT1dIpqskeym52nY+elBAt+v4e8h0fnP4sZmBZAI8DuHVcG6iHGrpEE8wJj5anEAUJuCjoYzkLHxtgnMdoGxFbiaWFRn0F/FQCa6kefXFIugZCQxtXm9XKf3nFDgZ+YG2qR9JLEquip/W7e8AQ36gIAfxuAQhI6JhmYunHjda8tWMIIKC1hugeco+h2tc5HOcUfst3P4B87AwIDAQABo4HqMIHnMA4GA1UdDwEB/wQEAwIBBjBMBgNVHR8ERTBDMEGgP6A9hjtodHRwOi8vbG9jYWxob3N0Ojk5OTkvcGtpLWZhY3RvcnkvY3JsL29jc3Atc2tpcC1yb290LWNhLmNybDBXBggrBgEFBQcBAQRLMEkwRwYIKwYBBQUHMAKGO2h0dHA6Ly9sb2NhbGhvc3Q6OTk5OS9wa2ktZmFjdG9yeS9jcnQvb2NzcC1za2lwLXJvb3QtY2EuY3J0MB0GA1UdDgQWBBQ24uC5SmzTkt35CLdzX7CO/rtmFDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQC4kWxZ36qCjVfwXsREF8NP4NtU7AVhKElzaiuP2JGB6ieMsPC3De1ojuSQ+joZkhGRy9w4Nx27neLPBuk9pCxj5EMzX3K2kFA4P5/izpbyJ6A/q2xK6Q9K4Kbpm3gG4MBElqrheRBaomnwrUQQKUovnsTZfgB+13K5CXvKDMZH0Mg2JM+URM8VFwgJb5fgeGbmzBoBSLdAUOexvZdreJhQIEIQjWxQGXmMtHRxU4ek/fK8z7img9uh4tGl1iNOCKFePhSLSJN7irP59bdxEqReRvffFWnFm3FNcs/a0UbLVnf4mlYhkcQoTHH3qbTW1GUEw947CgjWvHtQPSlLPOHf"));
        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.addTrustedCertSources(trustedCertificateSource);
        validator.setCertificateVerifier(certificateVerifier);
        return validator;
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
        assertEquals(1, certificateRevocationData.size());

        CertificateRevocationWrapper revocationWrapper = certificateRevocationData.get(0);
        assertEquals(RevocationType.OCSP, revocationWrapper.getRevocationType());
        assertTrue(revocationWrapper.getSigningCertificate().getNotAfter().before(revocationWrapper.getProductionDate()));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.XAdES_BASELINE_LT, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

}
