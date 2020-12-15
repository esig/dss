package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.TrustedListSignatureParametersBuilder;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

public class SignTrustedListTest extends CookbookTools {

    @Test
    public void sign() throws Exception {

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            // tag::demo[]
            DSSDocument trustedList = new FileDocument("src/main/resources/trusted-list.xml");

            DSSPrivateKeyEntry privateKeyEntry = signingToken.getKeys().get(0);
            CertificateToken signingCertificate = privateKeyEntry.getCertificate();
            // optionally the certificate chain can be provided
            List<CertificateToken> certificateChain = Arrays.asList(privateKeyEntry.getCertificateChain());

            // This class creates the appropriated XAdESSignatureParameters object to sign a trusted list.
            // It handles the configuration complexity and creates a ready-to-be-used XAdESSignatureParameters with the packaging, the references, the canononicalization,...
            TrustedListSignatureParametersBuilder builder = new TrustedListSignatureParametersBuilder(signingCertificate, certificateChain, trustedList);
            XAdESSignatureParameters parameters = builder.build();

            XAdESService service = new XAdESService(new CommonCertificateVerifier());

            ToBeSigned dataToSign = service.getDataToSign(trustedList, parameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKeyEntry);
            DSSDocument signedTrustedList = service.signDocument(trustedList, parameters, signatureValue);

            // end::demo[]

            testFinalDocument(signedTrustedList);
        }

    }

}
