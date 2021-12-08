package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.TrustedListSignatureParametersBuilder;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import eu.europa.esig.trustedlist.TrustedListUtils;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import javax.xml.transform.dom.DOMSource;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SignTrustedListTest extends CookbookTools {

    @Test
    public void sign() throws Exception {

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            // tag::demo[]
            DSSDocument trustedList = new FileDocument("src/main/resources/trusted-list.xml");

            DSSPrivateKeyEntry privateKeyEntry = signingToken.getKeys().get(0);
            CertificateToken signingCertificate = privateKeyEntry.getCertificate();

            // This class creates the appropriated XAdESSignatureParameters object to sign a trusted list.
            // It handles the configuration complexity and creates a ready-to-be-used XAdESSignatureParameters with a correct configuration.
            TrustedListSignatureParametersBuilder builder = new TrustedListSignatureParametersBuilder(signingCertificate, trustedList);
            XAdESSignatureParameters parameters = builder.build();

            XAdESService service = new XAdESService(new CommonCertificateVerifier());

            ToBeSigned dataToSign = service.getDataToSign(trustedList, parameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKeyEntry);
            DSSDocument signedTrustedList = service.signDocument(trustedList, parameters, signatureValue);

            // end::demo[]

            testFinalDocument(signedTrustedList);

            // tag::validate[]

            // Create an instance of a trusted certificate source
            // NOTE: signing-certificate of a TL shall be trusted directly
            CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
            trustedCertSource.addCertificate(getSigningCert());

            // First, we need a Certificate verifier (online sources are not required for TL-validation)
            CertificateVerifier cv = new CommonCertificateVerifier();
            cv.addTrustedCertSources(trustedCertSource);

            // We create an instance of XMLDocumentValidator
            DocumentValidator documentValidator = new XMLDocumentValidator(signedTrustedList);

            // We add the certificate verifier
            documentValidator.setCertificateVerifier(cv);

            // TL shall be valid at the validation time
            documentValidator.setValidationLevel(ValidationLevel.BASIC_SIGNATURES);

            // Here, everything is ready. We can execute the validation.
            Reports reports = documentValidator.validateDocument();

            // Additionally, the TL can be validated against the XSD schema
            Document tlDocDom = DomUtils.buildDOM(signedTrustedList);
            List<String> errors = TrustedListUtils.getInstance().validateAgainstXSD(new DOMSource(tlDocDom));
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
