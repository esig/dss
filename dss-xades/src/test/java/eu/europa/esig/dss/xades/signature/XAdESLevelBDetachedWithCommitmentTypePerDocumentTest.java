package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.CommonCommitmentType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import eu.europa.esig.dss.xades.reference.CanonicalizationTransform;
import eu.europa.esig.dss.xades.reference.DSSReference;
import org.junit.jupiter.api.BeforeEach;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

// See DSS-2742
public class XAdESLevelBDetachedWithCommitmentTypePerDocumentTest extends AbstractXAdESMultipleDocumentsSignatureService {

    private XAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentToSigns;

    @BeforeEach
    public void init() throws Exception {
        DSSDocument doc = new FileDocument("src/test/resources/sample.xml");
        DSSDocument declaration = new FileDocument("src/test/resources/sampleWithPlaceOfSignature.xml");

        documentToSigns = Arrays.asList(doc, declaration);

        signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        DSSReference docReference = new DSSReference();
        docReference.setContents(doc);
        docReference.setTransforms(Collections.singletonList(new CanonicalizationTransform(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS)));
        docReference.setId("xmldsig-ref0");
        docReference.setUri(doc.getName());

        DSSReference declReference = new DSSReference();
        declReference.setContents(declaration);
        declReference.setTransforms(Collections.singletonList(new CanonicalizationTransform(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS)));
        declReference.setId("xmldsig-ref1");
        declReference.setUri(declaration.getName());

        CommonCommitmentType commitmentDoc = new CommonCommitmentType();
        commitmentDoc.setUri("urn:sbr:signature-policy:proof-of-integrity-of-the-object-for-which-the-practitioner-expresses-an-opinion");
        commitmentDoc.setSignedDataObjects("xmldsig-ref0");

        CommonCommitmentType commitmentDecl = new CommonCommitmentType();
        commitmentDecl.setUri("urn:sbr:signature-policy:proof-of-intent-of-practitioner-to-add-a-copy-of-the-opinion");
        commitmentDecl.setSignedDataObjects("xmldsig-ref1");

        signatureParameters.setReferences(Arrays.asList(docReference, declReference));
        signatureParameters.bLevel().setCommitmentTypeIndications(Arrays.asList(commitmentDoc, commitmentDecl));
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return documentToSigns;
    }

    @Override
    protected MultipleDocumentsSignatureService<XAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return new XAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected XAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return documentToSigns;
    }

}
