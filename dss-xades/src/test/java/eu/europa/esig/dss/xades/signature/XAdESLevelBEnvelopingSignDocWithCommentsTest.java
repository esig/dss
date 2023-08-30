package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.DSSObject;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xml.DomUtils;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.Reference;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

// See DSS-3105
@Tag("slow")
public class XAdESLevelBEnvelopingSignDocWithCommentsTest extends AbstractXAdESTestSignature {

    private DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> service;
    private XAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private static Stream<Arguments> data() {
        String[] refUris = { "#ID", "#xpointer(id('ID'))" };
        String[] canonicalizations = { Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
                Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS, Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS, Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS };
        return random(refUris, canonicalizations);
    }

    static Stream<Arguments> random(String[] refUris, String[] canonicalizations) {
        List<Arguments> args = new ArrayList<>();
        for (String refUri : refUris) {
            for (String canonicalization : canonicalizations) {
                args.add(Arguments.of(refUri, canonicalization));
            }
        }
        return args.stream();
    }

    @ParameterizedTest(name = "Sign Enveloping XAdES {index} : {0} - {1}")
    @MethodSource("data")
    public void test(String refUri, String canonicalization) {
        documentToSign = new FileDocument(new File("src/test/resources/sample-with-comments.xml"));
        service = new XAdESService(getOfflineCertificateVerifier());

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.setEmbedXML(true);

        final List<DSSReference> references = new ArrayList<>();

        DSSReference dssReference = new DSSReference();
        dssReference.setId("r-" + documentToSign.getName());
        dssReference.setUri(refUri);
        dssReference.setType(Reference.OBJECT_URI);
        dssReference.setContents(documentToSign);
        dssReference.setDigestMethodAlgorithm(signatureParameters.getDigestAlgorithm());

        DSSObject dssObject = new DSSObject();
        dssObject.setContent(documentToSign);
        dssObject.setId("ID");
        dssReference.setObject(dssObject);

        final List<DSSTransform> transforms = new ArrayList<>();

        CanonicalizationTransform dssTransform = new CanonicalizationTransform(canonicalization);
        transforms.add(dssTransform);

        dssReference.setTransforms(transforms);
        references.add(dssReference);

        signatureParameters.setReferences(references);
        super.signAndVerify();
    }

    @Override
    public void signAndVerify() {
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        super.verifyOriginalDocuments(validator, diagnosticData);

        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(1, signatures.size());

        List<DSSDocument> originalDocuments = validator.getOriginalDocuments(signatures.get(0));
        assertEquals(1, originalDocuments.size());

        byte[] retrievedDoc = DomUtils.serializeNode(DomUtils.buildDOM(originalDocuments.get(0)));
        assertArrayEquals(DomUtils.serializeNode(DomUtils.buildDOM(documentToSign)), retrievedDoc);

        String strDoc = new String(retrievedDoc);
        assertTrue(strDoc.contains("<!-- Comment 1 -->"));
        assertTrue(strDoc.contains("<!-- Comment 2 -->"));
        assertTrue(strDoc.contains("<test>Hello World !</test>"));
        assertTrue(strDoc.contains("<!-- Comment 3 -->"));
    }

    @Override
    protected DocumentSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
