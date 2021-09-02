package eu.europa.esig.dss.validation.scope;

import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.Collections;
import java.util.List;

/**
 * This class is used to find a signature scope for an embedded timestamp
 * from a collection of {@code SignatureScope} candidates, extracted from a signature
 *
 */
public class EncapsulatedTimestampScopeFinder extends AbstractSignatureScopeFinder implements TimestampScopeFinder {

    /** {@code AdvancedSignature} embedding the timestamp */
    protected AdvancedSignature signature;

    /**
     * This method sets an encapsulating {@code AdvancedSignature}
     *
     * @param signature {@link AdvancedSignature}
     */
    public void setSignature(AdvancedSignature signature) {
        this.signature = signature;
    }

    @Override
    public List<SignatureScope> findTimestampScope(TimestampToken timestampToken) {
        if (timestampToken.isMessageImprintDataIntact()) {
            return filterCoveredSignatureScopes(timestampToken);
        }
        return Collections.emptyList();
    }

    /**
     * This method filters and returns covered {@code SignatureScope}s by the current timestamp
     *
     * @param timestampToken {@link TimestampToken}
     * @return a list of {@link SignatureScope}s
     */
    protected List<SignatureScope> filterCoveredSignatureScopes(TimestampToken timestampToken) {
        // return all by default
        return signature.getSignatureScopes();
    }

}
