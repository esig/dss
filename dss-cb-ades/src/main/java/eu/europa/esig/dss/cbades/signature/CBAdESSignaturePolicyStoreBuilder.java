package eu.europa.esig.dss.cbades.signature;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORTags;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.CBAdESUtils;
import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.cbades.validation.CBAdESUHeaders;
import eu.europa.esig.dss.cbades.validation.COSEDocumentAnalyzer;
import eu.europa.esig.dss.cbades.validation.COSEDocumentAnalyzerFactory;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignaturePolicyStore;
import eu.europa.esig.dss.model.SpDocSpecification;
import eu.europa.esig.dss.model.signature.SignaturePolicy;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.policy.SignaturePolicyValidator;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;

/**
 * The builder used to incorporate a {@code SignaturePolicyStore} to a
 * CBAdESSignature document
 *
 */
public class CBAdESSignaturePolicyStoreBuilder extends CBAdESExtensionBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(CBAdESSignaturePolicyStoreBuilder.class);

    /**
     * Default constructor
     */
    public CBAdESSignaturePolicyStoreBuilder() {
        // empty
    }

    /**
     * Adds {@code signaturePolicyStore} to all signatures inside the {@code document}
     * matching the given {@code SignaturePolicyStore}.
     *
     * @param document             {@link DSSDocument} containing CBAdES signatures to extend with
     *                             a {@link SignaturePolicyStore}
     * @param signaturePolicyStore {@link SignaturePolicyStore} to incorporate
     * @return {@link DSSDocument} containing signatures with {@code signaturePolicyStore}
     */
    public DSSDocument addSignaturePolicyStore(DSSDocument document, SignaturePolicyStore signaturePolicyStore) {
        Objects.requireNonNull(document, "Signature document must be provided!");
        assertConfigurationValid(signaturePolicyStore);

        final COSEDocumentAnalyzer documentAnalyzer = getDocumentAnalyzer(document);
        COSESignStructure coseSignStructure = documentAnalyzer.getCoseSignStructure();
        List<AdvancedSignature> signatures = documentAnalyzer.getSignatures();

        boolean signaturePolicyStoreAdded = false;
        for (AdvancedSignature signature : signatures) {
            boolean added = addSignaturePolicyStoreIfDigestMatch(
                    (CBAdESSignature) signature, signaturePolicyStore, documentAnalyzer);
            signaturePolicyStoreAdded = signaturePolicyStoreAdded || added;
        }
        if (!signaturePolicyStoreAdded) {
            throw new IllegalInputException("The process did not find a signature to add SignaturePolicyStore!");
        }

        byte[] serializedBytes = coseSignStructure.serialize();
        return new InMemoryDocument(serializedBytes);
    }

    /**
     * Adds {@code signaturePolicyStore} to a signature inside the {@code document}
     * with the given {@code signatureId}
     *
     * @param document             {@link DSSDocument} containing CBAdES signatures to extend with
     *                             a {@link SignaturePolicyStore}
     * @param signaturePolicyStore {@link SignaturePolicyStore} to incorporate
     * @param signatureId          {@link String} id of a signature to add SignaturePolicyStore for
     * @return {@link DSSDocument} containing signatures with {@code signaturePolicyStore}
     */
    public DSSDocument addSignaturePolicyStore(DSSDocument document, SignaturePolicyStore signaturePolicyStore,
                                               String signatureId) {
        Objects.requireNonNull(document, "Signature document must be provided!");
        assertConfigurationValid(signaturePolicyStore);

        final COSEDocumentAnalyzer documentAnalyzer = getDocumentAnalyzer(document);
        COSESignStructure coseSignStructure = documentAnalyzer.getCoseSignStructure();

        AdvancedSignature signature = documentAnalyzer.getSignatureById(signatureId);
        if (signature == null) {
            throw new IllegalInputException(String.format("Unable to find a signature with Id : %s!", signatureId));
        }

        boolean added = addSignaturePolicyStoreIfDigestMatch(
                (CBAdESSignature) signature, signaturePolicyStore, documentAnalyzer);
        if (!added) {
            throw new IllegalInputException(String.format(
                    "The process was not able to add SignaturePolicyStore to a signature with Id : %s!", signatureId));
        }

        byte[] serializedBytes = coseSignStructure.serialize();
        return new InMemoryDocument(serializedBytes);
    }

    /**
     * This method adds {@code SignaturePolicyStore} to a {@code cbadesSignature} if required
     *
     * @param cbadesSignature      {@link CBAdESSignature} signature to add {@link SignaturePolicyStore}
     * @param signaturePolicyStore {@link SignaturePolicyStore} to be added
     * @param documentAnalyzer     {@link COSEDocumentAnalyzer} used to extract the signature
     * @return TRUE if the signaturePolicyStore has been added for the particular signature, FALSE otherwise
     */
    protected boolean addSignaturePolicyStoreIfDigestMatch(CBAdESSignature cbadesSignature,
            SignaturePolicyStore signaturePolicyStore, COSEDocumentAnalyzer documentAnalyzer) {
        assertUHeadersComponentsConsistent(cbadesSignature);

        if (checkDigest(cbadesSignature, signaturePolicyStore, documentAnalyzer)) {
            CBORValue.CBORMapEditor docOrLocalURI = CBOR.map();

            DSSDocument signaturePolicyContent = signaturePolicyStore.getSignaturePolicyContent();
            if (signaturePolicyContent != null) {
                docOrLocalURI.put(COSEHeaderParameter.DOC_OR_LOCAL_URI_SIG_POL_DOC.cbor(),
                        DSSUtils.toByteArray(signaturePolicyContent));
            }

            String sigPolDocLocalURI = signaturePolicyStore.getSigPolDocLocalURI();
            if (Utils.isStringNotEmpty(sigPolDocLocalURI)) {
                docOrLocalURI.put(COSEHeaderParameter.DOC_OR_LOCAL_URI_SIG_POL_LOCAL_URI.cbor(),
                        CBORTags.uri(sigPolDocLocalURI));
            }

            CBORValue.CBORMapEditor sigPSt = CBOR.map();
            sigPSt.put(COSEHeaderParameter.SIG_PST_DOC_OR_LOCAL_URI.cbor(), docOrLocalURI.value());

            SpDocSpecification spDocSpecification = signaturePolicyStore.getSpDocSpecification();
            if (spDocSpecification != null) {
                CBORValue oidObject = CBAdESUtils.getOidObject(spDocSpecification.getId(),
                        spDocSpecification.getDescription(), spDocSpecification.getDocumentationReferences());
                sigPSt.put(COSEHeaderParameter.SIG_PST_SP_D_SPEC.cbor(), oidObject);
            }

            CBAdESUHeaders uHeaders = cbadesSignature.getUHeaders();
            uHeaders.addComponent(COSEHeaderParameter.SIG_PST.cbor(), sigPSt.value());

            return true;
        }

        return false;
    }

    /**
     * This method verifies if the digests computed in the provided {@code SignaturePolicyStore} match
     * the digest defined in the incorporated signature policy identifier
     *
     * @param CBAdESSignature      {@link CBAdESSignature} to check signature policy identifier
     * @param signaturePolicyStore {@link SignaturePolicyStore} to be incorporated
     * @param documentAnalyzer     {@link COSEDocumentAnalyzer}
     *                             JWS document validator used to extract the signature
     * @return TRUE if the digest match and {@link SignaturePolicyStore} can be embedded, FALSE otherwise
     */
    protected boolean checkDigest(CBAdESSignature CBAdESSignature, SignaturePolicyStore signaturePolicyStore,
                                  COSEDocumentAnalyzer documentAnalyzer) {
        final SignaturePolicy signaturePolicy = CBAdESSignature.getSignaturePolicy();
        if (signaturePolicy == null) {
            LOG.warn("No defined SignaturePolicyIdentifier for signature with Id : {}", CBAdESSignature.getId());
            return false;
        }
        final Digest expectedDigest = signaturePolicy.getDigest();
        if (expectedDigest == null) {
            LOG.warn("No defined digest for signature with Id : {}", CBAdESSignature.getId());
            return false;
        }

        DSSDocument signaturePolicyContent = signaturePolicyStore.getSignaturePolicyContent();
        if (signaturePolicyContent == null) {
            LOG.info("No policy document has been provided. Digests are not checked!");
            return true;
        }
        signaturePolicy.setPolicyContent(signaturePolicyContent);

        SignaturePolicyValidator validator = documentAnalyzer.getSignaturePolicyValidatorLoader().loadValidator(signaturePolicy);
        Digest computedDigest = validator.getComputedDigest(signaturePolicyContent, expectedDigest.getAlgorithm());

        boolean digestMatch = expectedDigest.equals(computedDigest);
        if (!digestMatch) {
            LOG.warn("Signature policy's digest {} doesn't match the digest extracted from document {} for signature with Id : {}",
                    computedDigest, expectedDigest, CBAdESSignature.getId());
        }
        return digestMatch;
    }

    private COSEDocumentAnalyzer getDocumentAnalyzer(DSSDocument document) {
        COSEDocumentAnalyzerFactory documentAnalyzerFactory = new COSEDocumentAnalyzerFactory();
        return documentAnalyzerFactory.create(document);
    }

    private void assertConfigurationValid(SignaturePolicyStore signaturePolicyStore) {
        Objects.requireNonNull(signaturePolicyStore, "SignaturePolicyStore must be provided");
        Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification(), "SpDocSpecification must be provided");
        Objects.requireNonNull(signaturePolicyStore.getSpDocSpecification().getId(), "ID (OID or URI) for SpDocSpecification must be provided");

        boolean signaturePolicyContentPresent = signaturePolicyStore.getSignaturePolicyContent() != null;
        boolean sigPolDocLocalURIPresent = signaturePolicyStore.getSigPolDocLocalURI() != null;
        if (signaturePolicyContentPresent == sigPolDocLocalURIPresent) {
            throw new IllegalArgumentException("SignaturePolicyStore shall contain either " +
                    "SignaturePolicyContent document or sigPolDocLocalURI!");
        }
    }

}
