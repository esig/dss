package eu.europa.esig.dss.validation.status;

import eu.europa.esig.dss.alert.status.ObjectStatus;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.AdvancedSignature;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Contains signatures concerned by an occurred event and corresponding information about them
 *
 */
public class SignatureStatus extends ObjectStatus {

    /** Map between signatures concerned by the check and corresponding error explanation messages */
    private final Map<AdvancedSignature, String> relatedSignatureMap = new HashMap<>();

    /**
     * Adds concerned signature and information about the occurred event
     *
     * @param signature {@link AdvancedSignature}
     * @param errorMessage {@link String} message
     */
    public void addRelatedTokenAndErrorMessage(AdvancedSignature signature, String errorMessage) {
        super.addRelatedObjectIdentifierAndErrorMessage(signature.getId(), errorMessage);
        relatedSignatureMap.put(signature, errorMessage);
    }

    /**
     * Returns a collection of signatures concerned by failure of the processed check
     *
     * @return a collection of {@link AdvancedSignature}s
     */
    public Collection<AdvancedSignature> getRelatedSignatures() {
        return relatedSignatureMap.keySet();
    }

    /**
     * Returns error message for the given signature
     *
     * @param signature {@link AdvancedSignature} to get caused error message for
     * @return {@link String} error message
     */
    public String getMessageForSignature(AdvancedSignature signature) {
        return relatedSignatureMap.get(signature);
    }

    @Override
    public boolean isEmpty() {
        return super.isEmpty() && Utils.isMapEmpty(relatedSignatureMap);
    }

}
