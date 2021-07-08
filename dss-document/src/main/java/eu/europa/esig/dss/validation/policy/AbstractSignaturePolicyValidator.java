package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;

/**
 * The abstract implementation of {@code SignaturePolicyValidator}
 *
 */
public abstract class AbstractSignaturePolicyValidator implements SignaturePolicyValidator {

    /** The error key to be used for general errors */
    protected static final String GENERAL_ERROR_KEY = "general";

    @Override
    public Digest getComputedDigest(DSSDocument policyDocument, DigestAlgorithm digestAlgorithm) {
        return DSSUtils.getDigest(digestAlgorithm, policyDocument);
    }

}
