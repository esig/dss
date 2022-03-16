package eu.europa.esig.dss.asic.xades.merge;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.asic.common.ASiCUtils;
import eu.europa.esig.dss.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import org.apache.xml.security.signature.Reference;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * This class is used to merge ASiC-S with XAdES containers.
 *
 */
public class ASiCSWithXAdESContainerMerger extends AbstractASiCWithXAdESContainerMerger {

    /**
     * Empty constructor
     */
    ASiCSWithXAdESContainerMerger() {
    }

    /**
     * This constructor is used to create an ASiC-S With XAdES container merger from provided container documents
     *
     * @param containerOne {@link DSSDocument} first container to be merged
     * @param containerTwo {@link DSSDocument} second container to be merged
     */
    public ASiCSWithXAdESContainerMerger(DSSDocument containerOne, DSSDocument containerTwo) {
        super(containerOne, containerTwo);
    }

    /**
     * This constructor is used to create an ASiC-S With XAdES from to given {@code ASiCContent}s
     *
     * @param asicContentOne {@link ASiCContent} first ASiC Content to be merged
     * @param asicContentTwo {@link ASiCContent} second ASiC Content to be merged
     */
    public ASiCSWithXAdESContainerMerger(ASiCContent asicContentOne, ASiCContent asicContentTwo) {
        super(asicContentOne, asicContentTwo);
    }

    @Override
    public boolean isSupported(DSSDocument container) {
        return super.isSupported(container) && !ASiCUtils.isASiCEContainer(container);
    }

    @Override
    public boolean isSupported(ASiCContent asicContent) {
        return super.isSupported(asicContent) && !ASiCUtils.isASiCEContainer(asicContent);
    }

    @Override
    protected void ensureContainerContentAllowMerge() {
        List<DSSDocument> signatureDocumentsOne = asicContentOne.getSignatureDocuments();
        List<DSSDocument> signatureDocumentsTwo = asicContentTwo.getSignatureDocuments();
        if (Utils.isCollectionEmpty(signatureDocumentsOne) && Utils.isCollectionEmpty(signatureDocumentsTwo)) {
            return; // no signatures -> can merge
        }

        if (Utils.collectionSize(signatureDocumentsOne) > 1 || Utils.collectionSize(signatureDocumentsTwo) > 1) {
            throw new UnsupportedOperationException("Unable to merge two ASiC-S with XAdES containers. " +
                    "One of the containers has more than one signature documents!");
        }
        if (Utils.isCollectionNotEmpty(signatureDocumentsOne) && Utils.isCollectionNotEmpty(signatureDocumentsTwo)) {
            DSSDocument signatureDocumentOne = signatureDocumentsOne.get(0);
            DSSDocument signatureDocumentTwo = signatureDocumentsTwo.get(0);
            if (!ASiCUtils.SIGNATURES_XML.equals(signatureDocumentOne.getName()) || !ASiCUtils.SIGNATURES_XML.equals(signatureDocumentTwo.getName())) {
                throw new UnsupportedOperationException("Unable to merge two ASiC-S with XAdES containers. " +
                        "The signature document in one of the containers has invalid naming!");
            }
        }

        List<DSSDocument> timestampDocumentsOne = asicContentOne.getTimestampDocuments();
        List<DSSDocument> timestampDocumentsTwo = asicContentTwo.getTimestampDocuments();
        if (Utils.isCollectionNotEmpty(timestampDocumentsOne) || Utils.isCollectionNotEmpty(timestampDocumentsTwo)) {
            throw new UnsupportedOperationException("Unable to merge two ASiC-S with XAdES containers. " +
                    "One of the containers contains a detached timestamp!");
        }

        List<DSSDocument> signedDocumentsOne = asicContentOne.getSignedDocuments();
        List<DSSDocument> signedDocumentsTwo = asicContentTwo.getSignedDocuments();
        if (Utils.collectionSize(signedDocumentsOne) > 1 || Utils.collectionSize(signedDocumentsTwo) > 1) {
            throw new UnsupportedOperationException("Unable to merge two ASiC-S with XAdES containers. " +
                    "One of the containers has more than one signer documents!");
        }

        if (Utils.isCollectionNotEmpty(signedDocumentsOne) && Utils.isCollectionNotEmpty(signedDocumentsTwo)) {
            DSSDocument signedDocumentOne = signedDocumentsOne.get(0);
            DSSDocument signedDocumentTwo = signedDocumentsTwo.get(0);
            if (signedDocumentOne.getName() == null || !signedDocumentOne.getName().equals(signedDocumentTwo.getName())) {
                throw new UnsupportedOperationException("Unable to merge two ASiC-S with XAdES containers. " +
                        "Signer documents have different names!");
            }
        }
    }

    @Override
    protected void ensureSignaturesAllowMerge() {
        if (Utils.isCollectionEmpty(asicContentOne.getSignatureDocuments()) ||
                Utils.isCollectionEmpty(asicContentTwo.getSignatureDocuments())) {
            // one of the containers does not contain a signature document. Can merge.
            return;
        }

        DSSDocument signatureDocumentOne = asicContentOne.getSignatureDocuments().get(0);
        DSSDocument signatureDocumentTwo = asicContentTwo.getSignatureDocuments().get(0);

        XMLDocumentValidator documentValidatorOne = new XMLDocumentValidator(signatureDocumentOne);
        XMLDocumentValidator documentValidatorTwo = new XMLDocumentValidator(signatureDocumentTwo);

        List<AdvancedSignature> signaturesOne = documentValidatorOne.getSignatures();
        List<AdvancedSignature> signaturesTwo = documentValidatorTwo.getSignatures();

        if (!checkNoCommonIdsBetweenSignatures(signaturesOne, signaturesTwo)) {
            throw new IllegalInputException("Signature documents contain signatures with the same identifiers!");
        }
        if (!checkNoCommonIdsBetweenSignedData(signaturesOne, signaturesTwo)) {
            throw new IllegalInputException("Signature documents contain signatures signed enveloped objects with the same identifiers!");
        }
        if (!checkNoCommonIdsBetweenSignatureValues(signaturesOne, signaturesTwo)) {
            throw new IllegalInputException("Signature documents contain signatures with SignatureValue elements sharing the same ids!");
        }
        assertSameRootElement(documentValidatorOne, documentValidatorTwo);

        DSSDocument signaturesXml = getMergedSignaturesXml(documentValidatorOne, documentValidatorTwo);
        asicContentOne.setSignatureDocuments(Collections.singletonList(signaturesXml));
        asicContentTwo.setSignatureDocuments(Collections.emptyList());
    }

    private boolean checkNoCommonIdsBetweenSignatures(List<AdvancedSignature> signaturesOne,
                                                      List<AdvancedSignature> signaturesTwo) {
        List<String> signatureIdsOne = getSignatureIds(signaturesOne);
        List<String> signatureIdsTwo = getSignatureIds(signaturesTwo);
        return !intersect(signatureIdsOne, signatureIdsTwo);
    }

    private List<String> getSignatureIds(List<AdvancedSignature> signatures) {
        return signatures.stream().map(AdvancedSignature::getDAIdentifier).collect(Collectors.toList());
    }

    private boolean checkNoCommonIdsBetweenSignedData(
            List<AdvancedSignature> signaturesOne, List<AdvancedSignature> signaturesTwo) {
        List<String> signedDataObjectIdsOne = getSignedDataObjectIds(signaturesOne);
        List<String> signedDataObjectIdsTwo = getSignedDataObjectIds(signaturesTwo);
        return !intersect(signedDataObjectIdsOne, signedDataObjectIdsTwo);
    }

    private List<String> getSignedDataObjectIds(List<AdvancedSignature> signatures) {
        List<String> ids = new ArrayList<>();
        for (AdvancedSignature signature : signatures) {
            XAdESSignature xadesSignature = (XAdESSignature) signature;
            List<Reference> references = xadesSignature.getReferences();
            for (Reference reference : references) {
                String referenceURI = DSSXMLUtils.getReferenceURI(reference);
                if (referenceURI != null) {
                    if (Utils.EMPTY_STRING.equals(referenceURI)) {
                        throw new IllegalInputException(
                                "Unable to merge signatures, as one of them covers the whole signature file document!");
                    }
                    if (DomUtils.startsFromHash(referenceURI) || DomUtils.isXPointerQuery(referenceURI)) {
                        // identifiers referencing objects within the document should be analyzed
                        ids.add(referenceURI);
                    }
                }
            }
        }
        return ids;
    }

    private boolean checkNoCommonIdsBetweenSignatureValues(List<AdvancedSignature> signaturesOne,
                                                           List<AdvancedSignature> signaturesTwo) {
        List<String> signatureValueIdsOne = getSignatureValueIds(signaturesOne);
        List<String> signatureValueIdsTwo = getSignatureValueIds(signaturesTwo);
        return !intersect(signatureValueIdsOne, signatureValueIdsTwo);
    }

    private List<String> getSignatureValueIds(List<AdvancedSignature> signatures) {
        List<String> ids = new ArrayList<>();
        for (AdvancedSignature signature : signatures) {
            XAdESSignature xadesSignature = (XAdESSignature) signature;
            ids.add(xadesSignature.getSignatureValueId());
        }
        return ids;
    }

    private void assertSameRootElement(XMLDocumentValidator documentValidatorOne,
                                         XMLDocumentValidator documentValidatorTwo) {
        Element rootElementOne = documentValidatorOne.getRootElement().getDocumentElement();
        Element rootElementTwo = documentValidatorTwo.getRootElement().getDocumentElement();
        if (!rootElementOne.getLocalName().equals(rootElementTwo.getLocalName())) {
            throw new IllegalInputException("Signature containers have different root elements!");
        }
        if (rootElementOne.getNamespaceURI() != null ^ rootElementTwo.getNamespaceURI() != null) {
            throw new IllegalInputException("Signature containers have different namespaces!");
        }
        if (rootElementOne.getNamespaceURI() != null && !rootElementOne.getNamespaceURI().equals(rootElementTwo.getNamespaceURI())) {
            throw new IllegalInputException("Signature containers have different namespaces!");
        }
        if (!rootElementOne.getPrefix().equals(rootElementTwo.getPrefix())) {
            throw new IllegalInputException("Signature containers have different namespace prefixes!");
        }
    }

    private DSSDocument getMergedSignaturesXml(XMLDocumentValidator documentValidatorOne,
                                               XMLDocumentValidator documentValidatorTwo) {
        Document document = documentValidatorOne.getRootElement();
        Element documentElement = document.getDocumentElement();

        NodeList childNodesToAdd = documentValidatorTwo.getRootElement().getDocumentElement().getChildNodes();
        for (int i = 0; i < childNodesToAdd.getLength(); i++) {
            Node node = childNodesToAdd.item(i);
            Node adopted = document.importNode(node, true);
            documentElement.appendChild(adopted);
        }

        byte[] bytes = DSSXMLUtils.serializeNode(documentElement);
        return new InMemoryDocument(bytes, ASiCUtils.SIGNATURES_XML, MimeType.XML);
    }

}
