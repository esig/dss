/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.validation;

import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

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

        validationDataForInclusion.addValidationData(getValidationDataForSignature(signature));
        validationDataForInclusion.addValidationData(getValidationDataForSignatureTimestamps(signature));
        validationDataForInclusion.addValidationData(getValidationDataForCounterSignatures(signature));
        validationDataForInclusion.addValidationData(getValidationDataForCounterSignatureTimestamps(signature));

        return validationDataForInclusion;
    }

    /**
     * Returns a complete validation data for a signature, including the data for incorporated timestamps
     * and/or counter-signatures, but excluding the tokens already incorporated within the signature
     *
     * @param signature {@link AdvancedSignature} to extract validation data for
     * @return {@link ValidationData}
     * @deprecated since DSS 6.2. Please use {@code #getAllValidationDataForSignatureForInclusion} method instead.
     */
    @Deprecated
    public ValidationData getCompleteValidationDataForSignature(final AdvancedSignature signature) {
        return getAllValidationDataForSignatureForInclusion(signature);
    }

    /**
     * Returns a complete validation data for a signature, including the data for incorporated timestamps
     * and/or counter-signatures, but excluding the tokens already incorporated within the signature
     *
     * @param signature {@link AdvancedSignature} to extract validation data for
     * @return {@link ValidationData}
     */
    public ValidationData getAllValidationDataForSignatureForInclusion(final AdvancedSignature signature) {
        ValidationData validationDataForInclusion = new ValidationData();

        validationDataForInclusion.addValidationData(getValidationDataForSignatureForInclusion(signature));
        validationDataForInclusion.addValidationData(getValidationDataForSignatureTimestampsForInclusion(signature));
        validationDataForInclusion.addValidationData(getValidationDataForCounterSignaturesForInclusion(signature));
        validationDataForInclusion.addValidationData(getValidationDataForCounterSignatureTimestampsForInclusion(signature));

        return validationDataForInclusion;
    }

    private void excludePresentValidationData(ValidationData validationData, AdvancedSignature signature) {
        validationData.excludeCertificateTokens(signature.getCertificateSource().getCertificates());
        validationData.excludeCRLTokens(signature.getCRLSource().getAllRevocationBinaries());
        validationData.excludeOCSPTokens(signature.getOCSPSource().getAllRevocationBinaries());
    }

    /**
     * Returns all validation data for the signature
     *
     * @param signature {@link AdvancedSignature} to extract validation data for
     * @return {@link ValidationData}
     */
    protected ValidationData getValidationDataForSignature(final AdvancedSignature signature) {
        ValidationData validationDataForInclusion = new ValidationData();

        ValidationData signatureValidationData = getValidationData(signature);
        validationDataForInclusion.addValidationData(signatureValidationData);

        return validationDataForInclusion;
    }

    /**
     * Returns all validation data for a signature,
     * but excluding the tokens already incorporated within the signature
     *
     * @param signature {@link AdvancedSignature} to extract validation data for
     * @return {@link ValidationData}
     */
    public ValidationData getValidationDataForSignatureForInclusion(final AdvancedSignature signature) {
        ValidationData validationDataForInclusion = getValidationDataForSignature(signature);
        excludePresentValidationData(validationDataForInclusion, signature);
        return validationDataForInclusion;
    }

    /**
     * Returns all validation data for the incorporated counter-signatures
     *
     * @param signature {@link AdvancedSignature} to extract validation data for
     * @return {@link ValidationData}
     */
    protected ValidationData getValidationDataForCounterSignatures(final AdvancedSignature signature) {
        ValidationData validationDataForInclusion = new ValidationData();

        for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
            ValidationData counterSignatureValidationData = getValidationData(counterSignature);
            validationDataForInclusion.addValidationData(counterSignatureValidationData);
        }

        return validationDataForInclusion;
    }

    /**
     * Returns all validation data for incorporated counter-signatures,
     * but excluding the tokens already incorporated within the signature or counter-signatures
     *
     * @param signature {@link AdvancedSignature} to extract validation data for
     * @return {@link ValidationData}
     */
    public ValidationData getValidationDataForCounterSignaturesForInclusion(final AdvancedSignature signature) {
        ValidationData validationDataForInclusion = getValidationDataForCounterSignatures(signature);
        excludePresentValidationData(validationDataForInclusion, signature);
        for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
            excludePresentValidationData(validationDataForInclusion, counterSignature);
        }
        return validationDataForInclusion;
    }

    /**
     * Returns all validation data for the timestamps incorporated within the signature.
     *
     * @param signature {@link AdvancedSignature} to extract validation data for
     * @return {@link ValidationData}
     */
    protected ValidationData getValidationDataForSignatureTimestamps(final AdvancedSignature signature) {
        ValidationData validationDataForInclusion = new ValidationData();

        for (TimestampToken timestampToken : signature.getAllTimestamps()) {
            ValidationData timestampValidationData = getValidationData(timestampToken);
            validationDataForInclusion.addValidationData(timestampValidationData);
        }

        return validationDataForInclusion;
    }

    /**
     * Returns all validation data for the timestamps incorporated within the signature,
     * but excluding the tokens already incorporated within the signature
     *
     * @param signature {@link AdvancedSignature} to extract validation data for
     * @return {@link ValidationData}
     */
    public ValidationData getValidationDataForSignatureTimestampsForInclusion(final AdvancedSignature signature) {
        ValidationData validationDataForInclusion = getValidationDataForSignatureTimestamps(signature);
        excludePresentValidationData(validationDataForInclusion, signature);
        return validationDataForInclusion;
    }

    /**
     * Returns all validation data for the timestamps incorporated within counter signatures of the current signature.
     *
     * @param signature {@link AdvancedSignature} to extract validation data for
     * @return {@link ValidationData}
     */
    protected ValidationData getValidationDataForCounterSignatureTimestamps(final AdvancedSignature signature) {
        ValidationData validationDataForInclusion = new ValidationData();

        for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
            for (TimestampToken timestampToken : counterSignature.getAllTimestamps()) {
                ValidationData timestampValidationData = getValidationData(timestampToken);
                validationDataForInclusion.addValidationData(timestampValidationData);
            }
        }

        return validationDataForInclusion;
    }

    /**
     * Returns all validation data for the timestamps incorporated within counter signatures of the current signature,
     * but excluding the tokens already incorporated within the signature
     *
     * @param signature {@link AdvancedSignature} to extract validation data for
     * @return {@link ValidationData}
     */
    public ValidationData getValidationDataForCounterSignatureTimestampsForInclusion(final AdvancedSignature signature) {
        ValidationData validationDataForInclusion = getValidationDataForCounterSignatureTimestamps(signature);
        excludePresentValidationData(validationDataForInclusion, signature);
        for (AdvancedSignature counterSignature : signature.getCounterSignatures()) {
            excludePresentValidationData(validationDataForInclusion, counterSignature);
        }
        return validationDataForInclusion;
    }

}
