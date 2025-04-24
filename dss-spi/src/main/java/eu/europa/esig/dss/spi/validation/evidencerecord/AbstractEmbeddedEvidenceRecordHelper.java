package eu.europa.esig.dss.spi.validation.evidencerecord;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.SignatureAttribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

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

    /** Map between digest algorithms and computed signature digest */
    private final Map<DigestAlgorithm, Digest> digestMap = new HashMap<>();

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

    /**
     * Gets the master signature embedding the evidence record
     *
     * @return {@link AdvancedSignature}
     */
    public AdvancedSignature getMasterSignature() {
        return signature;
    }

    @Override
    public Digest getMasterSignatureDigest(DigestAlgorithm digestAlgorithm) {
        return digestMap.computeIfAbsent(digestAlgorithm, this::createDigestDocument);
    }

    private Digest createDigestDocument(DigestAlgorithm digestAlgorithm) {
        try {
            return getDigestBuilder(signature, evidenceRecordAttribute, digestAlgorithm).build();

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

}
