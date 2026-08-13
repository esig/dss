package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cbades.signature.CBAdESService;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.cbades.validation.COSEDocumentValidator;
import eu.europa.esig.dss.cbades.vical.CborVICALSignatureParametersBuilder;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class SignVICALTest extends CookbookTools {

    @Test
    void sign() throws Exception {

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            // tag::demo[]
            // import eu.europa.esig.dss.model.DSSDocument;
            // import eu.europa.esig.dss.model.FileDocument;
            // import eu.europa.esig.dss.model.SignatureValue;
            // import eu.europa.esig.dss.model.ToBeSigned;
            // import eu.europa.esig.dss.model.x509.CertificateToken;
            // import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
            // import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
            // import eu.europa.esig.dss.cbades.CBAdESSignatureParameters;
            // import eu.europa.esig.dss.cbades.signature.CBAdESService;
            // import eu.europa.esig.dss.cbades.vical.CborVICALSignatureParametersBuilder;

            DSSDocument vical = new FileDocument("src/test/resources/snippets/vical.cbor");

            DSSPrivateKeyEntry privateKeyEntry = signingToken.getKeys().get(0);
            CertificateToken signingCertificate = privateKeyEntry.getCertificate();

            // This class creates the appropriated CBAdESSignatureParameters object
            // to sign a CBOR VICAL.
            // It handles the configuration complexity and creates a ready-to-be-used
            // CBAdESSignatureParameters with a correct configuration.
            CborVICALSignatureParametersBuilder builder = new CborVICALSignatureParametersBuilder(signingCertificate, vical);

            // NOTE: Structure validation is not yet supported

            // Build the parameters for CBOR VICAL signing
            CBAdESSignatureParameters parameters = builder.build();

            CBAdESService service = new CBAdESService(new CommonCertificateVerifier());

            ToBeSigned dataToSign = service.getDataToSign(vical, parameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKeyEntry);
            DSSDocument signedVical = service.signDocument(vical, parameters, signatureValue);

            // end::demo[]

            testFinalDocument(signedVical);

            // tag::validate[]
            // import eu.europa.esig.dss.DomUtils;
            // import eu.europa.esig.dss.enumerations.ValidationLevel;
            // import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
            // import eu.europa.esig.dss.spi.validation.CertificateVerifier;
            // import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
            // import eu.europa.esig.dss.validation.DocumentValidator;
            // import eu.europa.esig.dss.validation.reports.Reports;
            // import eu.europa.esig.dss.cbades.validation.COSEDocumentValidator;
            // import eu.europa.esig.trustedlist.TrustedListUtils;

            // Create an instance of a trusted certificate source
            // NOTE: signing-certificate of a TL shall be trusted directly
            CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
            trustedCertSource.addCertificate(getSigningCert());

            // First, we need a Certificate verifier (online sources are not required for TL-validation)
            CertificateVerifier cv = new CommonCertificateVerifier();
            cv.addTrustedCertSources(trustedCertSource);

            // We create an instance of COSEDocumentValidator
            DocumentValidator documentValidator = new COSEDocumentValidator(signedVical);

            // We add the certificate verifier
            documentValidator.setCertificateVerifier(cv);

            // TL shall be valid at the validation time
            documentValidator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);

            // Here, everything is ready. We can execute the validation.
            Reports reports = documentValidator.validateDocument();
            // end::validate[]

            assertNotNull(reports);
            DiagnosticData diagnosticData = reports.getDiagnosticData();
            DetailedReport detailedReport = reports.getDetailedReport();
            SimpleReport simpleReport = reports.getSimpleReport();

            assertNotNull(diagnosticData);
            assertNotNull(detailedReport);
            assertNotNull(simpleReport);
        }

    }

}
