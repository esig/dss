package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.merge.ASiCContainerMerger;
import eu.europa.esig.dss.asic.common.merge.DefaultContainerMerger;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESContainerExtractor;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This unit test displays a merging possibility of two ASiC-E with XAdES containers signing a different set of data.
 *
 */
public class SignTwoAsicAndMergeTest extends CookbookTools {

    @Test
    public void signAndMergeContainersTest() throws Exception {

        // Prepare documents to be signed
        List<DSSDocument> documentsToBeSignedByFirstSignature = Arrays.asList(
                new FileDocument("src/main/resources/xml_example.xml"),
                new FileDocument("src/main/resources/hello-world.pdf"));
        List<DSSDocument> documentsToBeSignedBySecondSignature = Arrays.asList(
                new FileDocument("src/test/resources/signature-pen.png"),
                new InMemoryDocument("Hello World!".getBytes(), "hello.txt", MimeType.TEXT));

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            // Preparing parameters for the ASiC-E with XAdES signature
            ASiCWithXAdESSignatureParameters parameters = new ASiCWithXAdESSignatureParameters();
            parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
            parameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());

            // Create ASiC service for signature
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            ASiCWithXAdESService service = new ASiCWithXAdESService(commonCertificateVerifier);

            // Create the first container signature
            ToBeSigned dataToSign = service.getDataToSign(documentsToBeSignedByFirstSignature, parameters);
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            DSSDocument firstContainerSignature = service.signDocument(documentsToBeSignedByFirstSignature, parameters, signatureValue);

            // Create the second container signature
            dataToSign = service.getDataToSign(documentsToBeSignedBySecondSignature, parameters);
            signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            DSSDocument secondContainerSignature = service.signDocument(documentsToBeSignedBySecondSignature, parameters, signatureValue);

            // tag::demo[]

            // DefaultContainerMerger will load a relevant implementation for the given containers
            ASiCContainerMerger asicContainerMerger = DefaultContainerMerger.fromDocuments(firstContainerSignature, secondContainerSignature);
            // merge() method will evaluate a technical possibility to execute the merge of two given containers
            // and will merge them into a single container, when possible
            DSSDocument mergedContainer = asicContainerMerger.merge();

            // end::demo[]

            ASiCWithXAdESContainerExtractor containerExtractor = new ASiCWithXAdESContainerExtractor(mergedContainer);
            ASiCContent asicContent = containerExtractor.extract();

            List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
            assertEquals(2, signatureDocuments.size());

            List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
            assertEquals(4, signedDocuments.size());

            List<String> signedDocumentNames = DSSUtils.getDocumentNames(signedDocuments);
            for (DSSDocument document : documentsToBeSignedByFirstSignature) {
                assertTrue(signedDocumentNames.contains(document.getName()));
            }
            for (DSSDocument document : documentsToBeSignedBySecondSignature) {
                assertTrue(signedDocumentNames.contains(document.getName()));
            }

            testFinalDocument(mergedContainer);
        }
    }

}
