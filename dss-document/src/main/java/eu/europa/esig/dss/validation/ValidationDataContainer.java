package eu.europa.esig.dss.validation;

import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Contains a {@code ValidationData} for a list of signatures/timestamps
 *
 */
public class ValidationDataContainer {

    /**
     * A map between signatures and their corresponding {@code ValidationData}
     */
    private final Map<AdvancedSignature, ValidationData> signatureValidationDataMap = new HashMap<>();

    /**
     * A map between timestamps and their corresponding {@code ValidationData}
     */
    private final Map<TimestampToken, ValidationData> timestampValidationDataMap = new HashMap<>();

    /**
     * Adds validation data to the container
     *
     * @param signature {@link AdvancedSignature}
     * @param validationData {@link ValidationData}
     */
    public void addValidationData(AdvancedSignature signature, ValidationData validationData) {
        signatureValidationDataMap.put(signature, validationData);
    }

    /**
     * Adds validation data to the container
     *
     * @param timestampToken {@link TimestampToken}
     * @param validationData {@link ValidationData}
     */
    public void addValidationData(TimestampToken timestampToken, ValidationData validationData) {
        timestampValidationDataMap.put(timestampToken, validationData);
    }

    /**
     * Returns a related {@code ValidationData} for the given token id
     *
     * @param signature {@link AdvancedSignature} to get {@link ValidationData} for
     * @return {@link ValidationData}
     */
    public ValidationData getValidationData(AdvancedSignature signature) {
        return signatureValidationDataMap.get(signature);
    }

    /**
     * Returns a related {@code ValidationData} for the given token id
     *
     * @param timestampToken {@link TimestampToken} to get {@link ValidationData} for
     * @return {@link ValidationData}
     */
    public ValidationData getValidationData(TimestampToken timestampToken) {
        return timestampValidationDataMap.get(timestampToken);
    }

    /**
     * Returns a combined validation data for all tokens
     *
     * @return {@link ValidationData}
     */
    public ValidationData getAllValidationData() {
        ValidationData result = new ValidationData();
        for (ValidationData validationData : signatureValidationDataMap.values()) {
            result.addValidationData(validationData);
        }
        for (ValidationData validationData : timestampValidationDataMap.values()) {
            result.addValidationData(validationData);
        }
        return result;
    }

    /**
     * Returns a collection of {@code AdvancedSignature}s
     *
     * @return a collection of {@link AdvancedSignature}s
     */
    public Collection<AdvancedSignature> getSignatures() {
        return signatureValidationDataMap.keySet();
    }

    /**
     * Checks if the validation data for inclusion if empty
     *
     * @return TRUE if the validation data container is empty, FALSE otherwise
     */
    public boolean isEmpty() {
        for (ValidationData validationData : signatureValidationDataMap.values()) {
            if (!validationData.isEmpty()) {
                return false;
            }
        }
        for (ValidationData validationData : timestampValidationDataMap.values()) {
            if (!validationData.isEmpty()) {
                return false;
            }
        }
        return true;
    }

}
