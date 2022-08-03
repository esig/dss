/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
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
     * Default constructor instantiating empty maps of tokens and validation data relationships
     */
    public ValidationDataContainer() {
        // empty
    }

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
     * Returns a collection of {@code TimestampToken}s
     *
     * @return a collection of {@link TimestampToken}s
     */
    public Collection<TimestampToken> getDetachedTimestamps() {
        return timestampValidationDataMap.keySet();
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

    /**
     * Returns a complete validation data for a signature, including the data for incorporated timestamps
     * and/or counter-signatures
     *
     * @param signature {@link AdvancedSignature} to extract validation data for
     * @return {@link ValidationData}
     */
    public ValidationData getAllValidationDataForSignature(final AdvancedSignature signature) {
        ValidationData validationDataForInclusion = new ValidationData();

        ValidationData signatureValidationData = getValidationData(signature);
        validationDataForInclusion.addValidationData(signatureValidationData);

        for (TimestampToken timestampToken : signature.getAllTimestamps()) {
            ValidationData timestampValidationData = getValidationData(timestampToken);
            validationDataForInclusion.addValidationData(timestampValidationData);
        }
        for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
            ValidationData counterSignatureValidationData = getValidationData(counterSignature);
            validationDataForInclusion.addValidationData(counterSignatureValidationData);
        }

        return validationDataForInclusion;
    }

    /**
     * Returns a complete validation data for a signature, including the data for incorporated timestamps
     * and/or counter-signatures, but excluding the tokens already incorporated within the signature
     *
     * @param signature {@link AdvancedSignature} to extract validation data for
     * @return {@link ValidationData}
     */
    public ValidationData getCompleteValidationDataForSignature(final AdvancedSignature signature) {
        ValidationData validationDataForInclusion = getAllValidationDataForSignature(signature);

        validationDataForInclusion.excludeCertificateTokens(signature.getCertificateSource().getCertificates());
        validationDataForInclusion.excludeCRLTokens(signature.getCRLSource().getAllRevocationBinaries());
        validationDataForInclusion.excludeOCSPTokens(signature.getOCSPSource().getAllRevocationBinaries());

        return validationDataForInclusion;
    }

}
