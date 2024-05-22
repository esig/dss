package eu.europa.esig.dss.xades.evidencerecord;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.evidencerecord.AbstractSignatureEvidenceRecordDigestBuilder;
import eu.europa.esig.dss.validation.evidencerecord.ByteArrayComparator;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.reference.ReferenceOutputType;
import eu.europa.esig.dss.xades.validation.XAdESAttribute;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xades.validation.XAdESUnsignedSigProperties;
import eu.europa.esig.dss.xades.validation.XMLDocumentValidator;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.XMLCanonicalizer;
import eu.europa.esig.xades.definition.XAdESPath;
import eu.europa.esig.xades.definition.xadesen.XAdESENElement;
import eu.europa.esig.xmldsig.definition.XMLDSigElement;
import eu.europa.esig.xmldsig.definition.XMLDSigPath;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.ReferenceNotInitializedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Computes message-imprint of an XML signature to be protected by an evidence-record
 *
 */
public class XAdESEvidenceRecordDigestBuilder extends AbstractSignatureEvidenceRecordDigestBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(XAdESEvidenceRecordDigestBuilder.class);

    /**
     * The list of detached documents covered by the signature
     */
    private List<DSSDocument> detachedContent;

    /**
     * DSS identifier or a signature's identifier of the signature to be covered by an evidence-record
     */
    private String signatureId;

    /**
     * Default constructor to instantiate XAdESEvidenceRecordDigestBuilder with a SHA-256 digest algorithm
     *
     * @param signatureDocument {@link DSSDocument} to compute message-imprint for
     */
    public XAdESEvidenceRecordDigestBuilder(final DSSDocument signatureDocument) {
        super(signatureDocument);
    }

    /**
     * Constructor to instantiate XAdESEvidenceRecordDigestBuilder with a custom digest algorithm
     *
     * @param signatureDocument {@link DSSDocument} to compute message-imprint for
     * @param digestAlgorithm {@link DigestAlgorithm} to be used
     */
    public XAdESEvidenceRecordDigestBuilder(final DSSDocument signatureDocument, final DigestAlgorithm digestAlgorithm) {
        super(signatureDocument, digestAlgorithm);
    }

    /**
     * Sets a list of detached documents covered by the signature
     *
     * @param detachedContent a list of detached {@link DSSDocument}s
     * @return this builder
     */
    public XAdESEvidenceRecordDigestBuilder setDetachedContent(List<DSSDocument> detachedContent) {
        this.detachedContent = detachedContent;
        return this;
    }

    /**
     * Sets identifier of the signature to be covered by an evidence-record. Accepts a DSS identifier,
     * or an internal signature element's identifier
     * Note: required for documents containing multiple signatures
     *
     * @param signatureId {@link String}
     * @return this builder
     */
    public XAdESEvidenceRecordDigestBuilder setSignatureId(String signatureId) {
        this.signatureId = signatureId;
        return this;
    }

    @Override
    public XAdESEvidenceRecordDigestBuilder setParallelEvidenceRecord(boolean parallelEvidenceRecord) {
        return (XAdESEvidenceRecordDigestBuilder) super.setParallelEvidenceRecord(parallelEvidenceRecord);
    }

    @Override
    public Digest build() {
        final XMLDocumentValidator documentValidator = new XMLDocumentValidator(signatureDocument);
        documentValidator.setDetachedContents(detachedContent);

        final List<AdvancedSignature> signatures = documentValidator.getSignatures();
        AdvancedSignature signature;
        if (Utils.collectionSize(signatures) == 0) {
            throw new IllegalInputException("The provided document does not contain any signature! " +
                    "Unable to compute message-imprint for an integrated evidence-record.");

        } else if (Utils.isStringNotEmpty(signatureId)) {
            signature = documentValidator.getSignatureById(signatureId);
            if (signature == null) {
                throw new IllegalArgumentException(
                        String.format("No signature with Id '%s' found in the document!", signatureId));
            }

        } else if (Utils.collectionSize(signatures) > 1) {
            throw new IllegalInputException("The provided document contains multiple signatures! " +
                    "Please use #setSignatureId method in order to provide the identifier.");

        } else {
            signature = signatures.get(0);
        }

        return getXmlSignatureMessageImprint((XAdESSignature) signature);
    }

    /**
     * Generates message-imprint for the given {@code XAdESSignature}
     *
     * @param signature {@link XAdESSignature} to be covered by an evidence-record
     * @return {@link Digest} of the signature
     */
    protected DSSMessageDigest getXmlSignatureMessageImprint(XAdESSignature signature) {
        try {
            /*
             * The initial time-stamp token encapsulated within the first ArchiveTimeStamp of any of
             * the evidence-records enclosed within the xadesen:SealingEvidenceRecords unsigned qualifying property,
             * shall incorporate a HashTree, whose first child shall contain the digest value of the group of
             * data objects listed below, concatenated in the order specified in IETF RFC 6283 [5] if
             * the xadesen:SealingEvidenceRecords unsigned qualifying property contains XMLERS evidence-records, or
             * in IETF RFC 4998 [8] if the xadesen:SealingEvidenceRecords unsigned qualifying property contains
             * ERS evidence-records:
             */
            final List<byte[]> dataObjectsGroup = new ArrayList<>();
            byte[] bytes = null;

            /*
             * 1) The data objects resulting of processing each ds:Reference element within ds:SignedInfo as
             * specified below:
             * - Process the ds:Reference element according to the reference processing model of XMLDSIG [7],
             *   clause 4.4.3.2.
             * - If the result is a XML node set, canonicalize using the canonicalization algorithm present in
             *   ds:CanonicalizationMethod element.
             */
            if (LOG.isTraceEnabled()) {
                LOG.trace("Step 1): Processing ds:Reference's within ds:SignedInfo");
            }
            // TODO : not clear which ds:CanonicalizationMethod to use. Using ds:SignedInfo/ds:CanonicalizationMethod for now
            final String canonicalizationAlgorithm = getCanonicalizationAlgorithm(signature);

            for (final Reference reference : signature.getReferences()) {
                bytes = getReferenceBytes(reference, canonicalizationAlgorithm);
                dataObjectsGroup.add(bytes);
            }

            /*
             * 2) The data objects resulting of taking the XMLDSIG elements listed below, and canonicalizing
             * each one using the canonicalization algorithm present in ds:CanonicalizationMethod element:
             * - The ds:SignedInfo element.
             * - The ds:SignatureValue element.
             * - The ds:KeyInfo element, if present.
             */
            if (LOG.isTraceEnabled()) {
                LOG.trace("Step 2): Canonicalization of ds:SignedInfo, ds:SignatureValue, ds:KeyInfo element");
            }
            bytes = getCanonicalizedValue(signature, XMLDSigPath.SIGNED_INFO_PATH, canonicalizationAlgorithm);
            dataObjectsGroup.add(bytes);

            bytes = getCanonicalizedValue(signature, XMLDSigPath.SIGNATURE_VALUE_PATH, canonicalizationAlgorithm);
            dataObjectsGroup.add(bytes);

            bytes = getCanonicalizedValue(signature, XMLDSigPath.KEY_INFO_PATH, canonicalizationAlgorithm);
            dataObjectsGroup.add(bytes);

            // Steps 3) and 4) are done together (signature is expected to be prepared)
            /*
             * 3) The data objects resulting of taking all the unsigned qualifying properties incorporated into the XAdES
             * signature except the xadesen:SealingEvidenceRecords element under construction, and
             * canonicalizing each one as specified in clause 4.5 of ETSI EN 319 132-1 [1].
             */
            /*
             * 4) As many xadesv141:TimeStampValidationData qualifying properties will be added as required for
             * incorporating the validation data, not already present in the XAdES signature, that are required for validating
             * all the time-stamp tokens incorporated (within signed or unsigned qualifying properties) into the XAdES
             * qualifying properties different than xadesen:SealingEvidenceRecords. Each xadesv141:TimeStampValidationData
             * shall be generated following the specifications of ETSI EN 319 132-1 [1]. For every
             * xadesv141:TimeStampValidationData qualifying property incorporated, the corresponding data object
             * resulting of canonicalizing this qualifying property as specified in clause 4.5 of ETSI EN 319 132-1 [1]
             * will be generated and added to the group of data objects to be time stamped.
             */
            if (LOG.isTraceEnabled()) {
                LOG.trace("Step 3): Processing of unsigned qualifying properties");
            }
            final XAdESUnsignedSigProperties unsignedSignatureProperties = getUnsignedSignatureProperties(signature);
            if (unsignedSignatureProperties != null) {
                for (XAdESAttribute xadesAttribute : unsignedSignatureProperties.getAttributes()) {
                    bytes = getCanonicalizedValue(xadesAttribute.getElement(), canonicalizationAlgorithm);
                    dataObjectsGroup.add(bytes);
                }
            }

            /*
             * 5) All the ds:Object elements except the one containing QualifyingProperties element, as specified
             * in step 5) of clause 5.5.2.2 of ETSI EN 319 132-1 [1].
             */
            if (LOG.isTraceEnabled()) {
                LOG.trace("Step 5): Processing of ds:Object's");
            }
            for (Node object : getObjects(signature)) {
                if (!containsQualifyingProperties(object, signature.getXAdESPaths())) {
                    bytes = getCanonicalizedValue(object, canonicalizationAlgorithm);
                    dataObjectsGroup.add(bytes);
                }
            }

            /*
             * 6) The objects derived from the presence of signed ds:Manifest elements. These objects shall be generated
             * as it is specified below:
             */
            if (LOG.isTraceEnabled()) {
                LOG.trace("Step 6): Processing of ds:Manifest's");
            }
            for (final Reference reference : signature.getReferences()) {
                if (reference.typeIsReferenceToManifest()) {
                    List<byte[]> manifestDataObjects = getManifestDataObjects(signature, reference, canonicalizationAlgorithm);
                    dataObjectsGroup.addAll(manifestDataObjects);
                }
            }

            // compute final digest
            final DSSMessageDigest dataGroupDigest = computeDigestValueGroupHash(dataObjectsGroup);
            if (LOG.isTraceEnabled()) {
                LOG.trace(String.format("Evidence-record signature data group digest: %s", dataGroupDigest));
            }
            return dataGroupDigest;

        } catch (XMLSecurityException e) {
            throw new DSSException(String.format("Unable to compute message-imprint for an evidence-record. " +
                    "Reason : %s", e.getMessage()), e);
        }
    }

    /**
     * Returns corresponding ds:CanonicalizationMethod used within the signature
     *
     * @param signature {@link XAdESSignature}
     * @return {@link String} canonicalization method identifier
     */
    protected String getCanonicalizationAlgorithm(XAdESSignature signature) {
        Element signedInfo = signature.getSignedInfo();
        if (signedInfo == null) {
            throw new IllegalStateException("ds:SignedInfo element shall be defined within a signature!");
        }
        String canonicalizationMethod = DomUtils.getValue(signedInfo, XMLDSigPath.CANONICALIZATION_ALGORITHM_PATH);
        if (Utils.isStringEmpty(canonicalizationMethod)) {
            LOG.warn("No canonicalization method found within ds:SignedInfo element. " +
                    "Re-use the default canonicalization algorithm 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'");
            canonicalizationMethod = XMLCanonicalizer.DEFAULT_XMLDSIG_C14N_METHOD;
        }
        return canonicalizationMethod;
    }

    private byte[] getReferenceBytes(final Reference reference, final String canonicalizationAlgorithm) throws XMLSecurityException {
        try {
            /*
             * 1) process the retrieved ds:Reference element according to the reference-processing model of XMLDSIG [1]
             * clause 4.4.3.2;
             */
            byte[] referencedBytes = reference.getReferencedBytes();
            /*
             * 2) If the result is a XML node set, canonicalize using the canonicalization algorithm present in
             *   ds:CanonicalizationMethod element.
             */
            if (isResultXmlNodeSet(reference, referencedBytes)) {
                referencedBytes = XMLCanonicalizer.createInstance(canonicalizationAlgorithm).canonicalize(referencedBytes);
            }
            if (LOG.isTraceEnabled()) {
                LOG.trace("ReferencedBytes : {}", new String(referencedBytes));
            }
            return referencedBytes;

        } catch (ReferenceNotInitializedException e) {
            throw new DSSException(String.format("An error occurred on ds:Reference processing. In case of detached signature, " +
                    "please use #setDetachedContent method to provide original documents. More information : %s", e.getMessage()), e);
        }
    }

    private byte[] getCanonicalizedValue(final XAdESSignature signature, final String xPathString, final String canonicalizationAlgorithm) {
        final Element element = DomUtils.getElement(signature.getSignatureElement(), xPathString);
        return getCanonicalizedValue(element, canonicalizationAlgorithm);
    }

    private byte[] getCanonicalizedValue(Node node, String canonicalizationAlgorithm) {
        if (node != null) {
            final byte[] bytes = XMLCanonicalizer.createInstance(canonicalizationAlgorithm).canonicalize(node);
            if (LOG.isTraceEnabled()) {
                LOG.trace("Canonicalized subtree string : \n{}", new String(bytes));
            }
            return bytes;
        }
        return null;
    }

    private XAdESUnsignedSigProperties getUnsignedSignatureProperties(XAdESSignature signature) {
        // NOTE : only direct incorporation is supported
        Element unsignedSignaturePropertiesDom = DomUtils.getElement(signature.getSignatureElement(), signature.getXAdESPaths().getUnsignedSignaturePropertiesPath());
        if (unsignedSignaturePropertiesDom == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("No xades:UnsignedSignatureProperties is present to compute the message-imprint for an evidence-record");
            }
            return null;
        }
        if (parallelEvidenceRecord) {
            NodeList unsignedSignatureProperties = unsignedSignaturePropertiesDom.getChildNodes();
            Node lastSealingEvidenceRecordNode = getLastSealingEvidenceRecordNode(unsignedSignatureProperties);
            if (lastSealingEvidenceRecordNode != null) {
                // Execute in reverse order in order to change only last evidence-record, when applicable
                boolean evidenceRecordNodeReached = false;
                for (int i = 0; i < unsignedSignatureProperties.getLength(); i++) {
                    Node childNode = unsignedSignatureProperties.item(i);
                    if (evidenceRecordNodeReached || lastSealingEvidenceRecordNode == childNode) {
                        unsignedSignaturePropertiesDom.removeChild(childNode);
                        evidenceRecordNodeReached = true;
                    }
                }
            }
        }
        return new XAdESUnsignedSigProperties(unsignedSignaturePropertiesDom, signature.getXAdESPaths());
    }

    private Node getLastSealingEvidenceRecordNode(NodeList unsignedSignatureProperties) {
        // Execute in reverse order in order to change only last evidence-record, when applicable
        for (int i = unsignedSignatureProperties.getLength() - 1; i >= 0; i--) {
            Node childNode = unsignedSignatureProperties.item(i);
            if (XAdESENElement.SEALING_EVIDENCE_RECORDS.isSameTagName(childNode.getLocalName())) {
                return childNode;
            }
        }
        return null;
    }

    private List<Node> getObjects(XAdESSignature signature) {
        NodeList objects = signature.getObjects();
        if (objects != null && objects.getLength() > 0) {
            final List<Node> result = new ArrayList<>();
            for (int i = 0; i < objects.getLength(); i++) {
                result.add(objects.item(i));
            }
            return result;
        }
        return Collections.emptyList();
    }

    private boolean containsQualifyingProperties(Node node, XAdESPath xadesPath) {
        Node qualifyingProperties = DomUtils.getNode(node, xadesPath.getCurrentQualifyingPropertiesPath());
        return qualifyingProperties != null;
    }

    private List<byte[]> getManifestDataObjects(XAdESSignature signature, Reference referenceToManifest,
                                                String canonicalizationAlgorithm) throws XMLSecurityException {
        final List<byte[]> dataObjectsGroup = new ArrayList<>();
        getManifestDataObjectsRecursively(signature, referenceToManifest, canonicalizationAlgorithm, dataObjectsGroup);
        return dataObjectsGroup;
    }

    private void getManifestDataObjectsRecursively(XAdESSignature signature, Reference referenceToManifest,
                                                           String canonicalizationAlgorithm, List<byte[]> dataObjectsGroup) throws XMLSecurityException {
        byte[] bytes;
        for (Reference manifestReference : getManifestReferences(signature, referenceToManifest)) {
            /*
             * a) For each ds:Reference child element of each signed ds:Manifest element retrieve the data
             *    object referenced by its URI attribute.
             */
            bytes = getReferenceBytes(manifestReference, canonicalizationAlgorithm);
            /*
             * b) If the retrieved data object is not a XML node set, or it is a XML node set different than a
             *    ds:Manifest element, process it as specified by the reference processing model of XMLDSIG [7],
             *    clause 4.4.3.2. The resulting data object shall be added to the group of data objects to be digested.
             */
            if (!isResultXmlNodeSet(manifestReference, bytes) || !isResultManifestElement(bytes)) {
                dataObjectsGroup.add(bytes);
            }
            /*
             * c) If the retrieved data object is a ds:Manifest element, apply the steps 6) a) to 6) c) recursively for
             *    generating the objects to be added to the group of data objects to be digested.
             */
            else {
                getManifestDataObjectsRecursively(signature, referenceToManifest, canonicalizationAlgorithm, dataObjectsGroup);
            }
        }
    }

    private List<Reference> getManifestReferences(XAdESSignature signature, Reference referenceToManifest) throws XMLSecurityException {
        String uri = referenceToManifest.getURI();
        Element manifestElement = DSSXMLUtils.getManifestById(signature.getSignatureElement(), uri);
        Manifest manifest = DSSXMLUtils.initManifestWithDetachedContent(manifestElement, detachedContent);
        return DSSXMLUtils.extractReferences(manifest);
    }

    private boolean isResultXmlNodeSet(Reference reference, byte[] referencedBytes) throws XMLSecurityException {
        return ReferenceOutputType.NODE_SET.equals(DSSXMLUtils.getReferenceOutputType(reference)) && DomUtils.isDOM(referencedBytes);
    }

    private boolean isResultManifestElement(byte[] referencedBytes) {
        final Document document = DomUtils.buildDOM(referencedBytes);
        final Element documentElement = document.getDocumentElement();
        return XMLDSigElement.MANIFEST.isSameTagName(documentElement.getLocalName()) &&
                XMLDSigElement.MANIFEST.getURI().equals(documentElement.getNamespaceURI());
    }

    private DSSMessageDigest computeDigestValueGroupHash(List<byte[]> dataObjectsGroup) {
        /*
         * The algorithm by which a root hash value is generated from the
         * <HashTree> element is as follows: the content of each <DigestValue>
         * element within the first <Sequence> element is base64 ([RFC4648],
         * using the base64 alphabet not the base64url alphabet) decoded to
         * obtain a binary value (representing the hash value). All collected
         * hash values from the sequence are ordered in binary ascending order,
         * concatenated and a new hash value is generated from that string.
         * With one exception to this rule: when the first <Sequence> element
         * has only one <DigestValue> element, then its binary value is added to
         * the next list obtained from the next <Sequence> element.
         */
        // 1. Group together items
        List<byte[]> digestValueGroup = dataObjectsGroup.stream().map(
                d -> DSSUtils.digest(digestAlgorithm, d)).collect(Collectors.toList());
        if (LOG.isTraceEnabled()) {
            LOG.trace("1. Digest Value Group:");
            digestValueGroup.forEach(d -> LOG.trace(Utils.toHex(d)));
        }
        // 2a. Exception
        if (Utils.collectionSize(digestValueGroup) == 1) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("2a. Only one data object: {}", digestValueGroup.get(0));
            }
            return new DSSMessageDigest(digestAlgorithm, digestValueGroup.get(0));
        }
        // 2b. Binary ascending sort
        digestValueGroup.sort(ByteArrayComparator.getInstance());
        if (LOG.isTraceEnabled()) {
            LOG.trace("2b. Sorted Digest Value Group:");
            digestValueGroup.forEach(d -> LOG.trace(Utils.toHex(d)));
        }
        // 3. Concatenate
        final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
        for (byte[] hashValue : digestValueGroup) {
            digestCalculator.update(hashValue);
        }
        // 4. Calculate hash value
        DSSMessageDigest messageDigest = digestCalculator.getMessageDigest();
        if (LOG.isTraceEnabled()) {
            LOG.trace("4. Message-digest of concatenated string: {}", messageDigest.getHexValue());
        }
        return messageDigest;
    }

}
