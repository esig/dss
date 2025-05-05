package eu.europa.esig.dss.spi.validation.evidencerecord;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.SignatureAttribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract implementation of {@code InternalEvidenceRecordHelper} containing common implementation methods
 *
 */
public abstract class AbstractEmbeddedEvidenceRecordHelper implements EmbeddedEvidenceRecordHelper {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractEmbeddedEvidenceRecordHelper.class);

    /** Master signature */
    protected final AdvancedSignature signature;

    /** Unsigned signature attribute embedding the evidence record */
    protected final SignatureAttribute evidenceRecordAttribute;

    /** Position of the attribute within the signature */
    private Integer orderOfAttribute;

    /** Position of the current evidence record within the evidence record attribute */
    private Integer orderWithinAttribute;

    /**
     * Default constructor
     *
     * @param signature {@link AdvancedSignature}
     * @param evidenceRecordAttribute {@link SignatureAttribute}
     */
    protected AbstractEmbeddedEvidenceRecordHelper(final AdvancedSignature signature,
                                                   final SignatureAttribute evidenceRecordAttribute) {
        this.signature = signature;
        this.evidenceRecordAttribute = evidenceRecordAttribute;
    }

    @Override
    public AdvancedSignature getMasterSignature() {
        return signature;
    }

    @Override
    public SignatureAttribute getEvidenceRecordAttribute() {
        return evidenceRecordAttribute;
    }

    @Override
    public Integer getOrderOfAttribute() {
        return orderOfAttribute;
    }

    /**
     * Sets position of the evidence record carrying attribute within the signature
     *
     * @param orderOfAttribute position of the attribute
     */
    public void setOrderOfAttribute(Integer orderOfAttribute) {
        this.orderOfAttribute = orderOfAttribute;
    }

    @Override
    public Integer getOrderWithinAttribute() {
        return orderWithinAttribute;
    }

    /**
     * Sets position of the evidence record within its carrying attribute
     *
     * @param orderWithinAttribute position of the evidence record within the attribute
     */
    public void setOrderWithinAttribute(Integer orderWithinAttribute) {
        this.orderWithinAttribute = orderWithinAttribute;
    }

    @Override
    public Digest getMasterSignatureDigest(DigestAlgorithm digestAlgorithm) {
        SignatureEvidenceRecordDigestBuilder digestBuilder = getDigestBuilder(signature, evidenceRecordAttribute, digestAlgorithm);
        return buildDigest(digestBuilder);
    }

    @Override
    public Digest getMasterSignatureDigest(DigestAlgorithm digestAlgorithm, boolean derEncoded) {
        SignatureEvidenceRecordDigestBuilder digestBuilder = getDigestBuilder(signature, evidenceRecordAttribute, digestAlgorithm);
        setDEREncoding(digestBuilder, derEncoded);
        return buildDigest(digestBuilder);
    }

    private Digest buildDigest(SignatureEvidenceRecordDigestBuilder digestBuilder) {
        try {
            return digestBuilder.build();

        } catch (Exception e) {
            String errorMessage = "Unable to compute master signature digest for an evidence record. Reason : {}";
            if (LOG.isDebugEnabled()) {
                LOG.warn(errorMessage, e.getMessage(), e);
            } else {
                LOG.warn(errorMessage, e.getMessage());
            }
            return new Digest(); // return empty digest
        }
    }

    /**
     * Gets implementation of the signature digest builder for the given evidence record
     *
     * @param signature {@link AdvancedSignature}
     * @param evidenceRecordAttribute {@link SignatureAttribute}
     * @param digestAlgorithm {@link DigestAlgorithm}
     * @return {@link SignatureEvidenceRecordDigestBuilder}
     */
    protected abstract SignatureEvidenceRecordDigestBuilder getDigestBuilder(AdvancedSignature signature,
            SignatureAttribute evidenceRecordAttribute, DigestAlgorithm digestAlgorithm);

    /**
     * Sets the {@code encoding} to be used on the hash computation
     * to the {@code SignatureEvidenceRecordDigestBuilder} whether applicable
     *
     * @param digestBuilder {@link SignatureEvidenceRecordDigestBuilder}
     * @param derEncoded whether signature shall be DER encoded
     */
    protected abstract void setDEREncoding(SignatureEvidenceRecordDigestBuilder digestBuilder, boolean derEncoded);

}
