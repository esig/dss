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
package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.model.Digest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Contains results of a {@code SignaturePolicy} validation
 *
 */
public class SignaturePolicyValidationResult {

    /** Indicated if the signature policy has been identified */
    private boolean identified = false;

    /** Indicates if the signature policy is of an ASN.1 format */
    private boolean asn1Processable = false;

    /** Indicates if digest algorithms match */
    private boolean digestAlgorithmsEqual = false;

    /** Indicated is the signature policy validation result is valid */
    private boolean digestValid = false;

    /** Defines the digest that have been computed on the provided policy document */
    private Digest digest;

    /** A list of stored errors occurred during signature policy processing */
    private Map<String, String> errors;

    /**
     * Default constructor instantiating object with null values
     */
    public SignaturePolicyValidationResult() {
        // empty
    }

    /**
     * Returns if the signature policy has been obtained successfully
     *
     * @return TRUE if the signature policy has been identified, FALSE otherwise
     */
    public boolean isIdentified() {
        return identified;
    }

    /**
     * Sets if the signature policy has been obtained successfully
     *
     * @param identified if the signature policy has been identified
     */
    public void setIdentified(boolean identified) {
        this.identified = identified;
    }

    /**
     * Returns if the signature policy has been validated successfully
     *
     * @return TRUE if the signature policy is valid, FALSE otherwise
     */
    public boolean isDigestValid() {
        return digestValid;
    }

    /**
     * Sets if the signature policy is valid
     *
     * @param digestValid if the signature policy is valid
     */
    public void setDigestValid(boolean digestValid) {
        this.digestValid = digestValid;
    }

    /**
     * Returns if the signature policy is ASN.1 processable
     *
     * @return TRUE if the policy of ASN.1 encoded format, FALSE otherwise
     */
    public boolean isAsn1Processable() {
        return asn1Processable;
    }

    /**
     * Sets if the signature policy is ASN.1 processable
     *
     * @param asn1Processable if the policy of ASN.1 encoded format
     */
    public void setAsn1Processable(boolean asn1Processable) {
        this.asn1Processable = asn1Processable;
    }

    /**
     * Returns if the DigestAlgorithm defined in the policy and used for the validation do match
     *
     * @return TRUE if the digest algorithms match, FALSE otherwise
     */
    public boolean isDigestAlgorithmsEqual() {
        return digestAlgorithmsEqual;
    }

    /**
     * Sets if the digest algorithms match
     *
     * @param digestAlgorithmsEqual if the digest algorithms match
     */
    public void setDigestAlgorithmsEqual(boolean digestAlgorithmsEqual) {
        this.digestAlgorithmsEqual = digestAlgorithmsEqual;
    }

    /**
     * Returns Digest that have been computed on the obtained signature policy document
     *
     * NOTE: can return NULL if a validator was not able to compute the digest
     *
     * @return {@link Digest} that have been computed in a signature policy document
     */
    public Digest getDigest() {
        return digest;
    }

    /**
     * Sets Digest that have been computed on the extracted signature policy document
     *
     * @param digest {@link Digest}
     */
    public void setDigest(Digest digest) {
        this.digest = digest;
    }

    /**
     * Returns a list of error messages occurred in the validation process
     *
     * @return a map of error keys and messages
     */
    protected Map<String, String> getErrors() {
        if (errors == null) {
            errors = new LinkedHashMap<>();
        }
        return errors;
    }

    /**
     * This method allows to add a new error message occurred during the validation
     *
     * @param errorKey {@link String} defines nature of the error
     * @param errorMessage {@link String} the error message
     */
    public void addError(String errorKey, String errorMessage) {
        Map<String, String> errors = getErrors();
        errors.put(errorKey, errorMessage);
    }

    /**
     * Returns a user-friendly {@code String} with obtained error messages occurred during the validation process
     *
     * @return {@link String} validation errors
     */
    public String getProcessingErrors() {
        StringBuilder stringBuilder = new StringBuilder();
        Map<String, String> errors = getErrors();
        if (!errors.isEmpty()) {
            stringBuilder.append("The errors found on signature policy validation are:");
            for (Map.Entry<String, String> entry : errors.entrySet()) {
                stringBuilder.append(" at ").append(entry.getKey()).append(": ").append(entry.getValue()).append(",");
            }
            stringBuilder.setLength(stringBuilder.length() - 1);
        }
        return stringBuilder.toString();
    }

}
