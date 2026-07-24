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
package eu.europa.esig.dss.ws.attestation.validation.dto;

import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.Date;

/**
 * Represents a request DTO for validation of an Attestation Presentation
 * 
 */
public class AttestationToValidateDTO {

    /**
     * The document that contains an Attestation Presentation to be validated
     */
    private RemoteDocument attestationPresentation;

    /**
     * Supplementary data for Attestation Presentation validation
     */
    private AttestationValidationParametersDTO attestationValidationParameters;
    
    /**
     * The custom validation policy to use
     * <p>
     * OPTIONAL.
     */
    private RemoteDocument policy;

    /**
     * The custom cryptographic suite to use
     * <p>
     * OPTIONAL.
     */
    private RemoteDocument cryptographicSuite;

    /**
     * Allows to specify a validation time different from the current time.
     * <p>
     * OPTIONAL.
     */
    private Date validationTime;

    /**
     * The strategy for the token (certificate/timestamp/revocation data) extraction
     * <p>
     * OPTIONAL.
     */
    private TokenExtractionStrategy tokenExtractionStrategy = TokenExtractionStrategy.NONE;

    /**
     * Empty constructor
     */
    public AttestationToValidateDTO() {
        // empty
    }

    /**
     * Constructor to validate an Attestation Presentation
     *
     * @param attestationPresentation {@link RemoteDocument} to validate
     */
    public AttestationToValidateDTO(RemoteDocument attestationPresentation) {
        this(attestationPresentation, (AttestationValidationParametersDTO) null);
    }

    /**
     * Constructor to validate an Attestation Presentation with supplementary validation parameters
     *
     * @param attestationPresentation {@link RemoteDocument} to validate
     * @param attestationValidationParameters {@link AttestationValidationParametersDTO}
     */
    public AttestationToValidateDTO(RemoteDocument attestationPresentation, AttestationValidationParametersDTO attestationValidationParameters) {
        this(attestationPresentation, attestationValidationParameters, null);
    }

    /**
     * Constructor to validate a document with a validation policy provided
     *
     * @param attestationPresentation {@link RemoteDocument} to validate
     * @param policy {@link RemoteDocument} validation policy
     */
    public AttestationToValidateDTO(RemoteDocument attestationPresentation, RemoteDocument policy) {
        this(attestationPresentation, policy, null);
    }

    /**
     * Constructor to validate a document with supplementary validation parameters and with a validation policy provided
     *
     * @param attestationPresentation {@link RemoteDocument} to validate
     * @param attestationValidationParameters {@link AttestationValidationParametersDTO}
     * @param policy {@link RemoteDocument} validation policy
     */
    public AttestationToValidateDTO(RemoteDocument attestationPresentation, AttestationValidationParametersDTO attestationValidationParameters, RemoteDocument policy) {
        this(attestationPresentation, attestationValidationParameters, policy, null);
    }

    /**
     * Constructor to validate a document with a validation policy and cryptographic suite provided
     *
     * @param attestationPresentation {@link RemoteDocument} to validate
     * @param policy {@link RemoteDocument} validation policy
     * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
     */
    public AttestationToValidateDTO(RemoteDocument attestationPresentation, RemoteDocument policy, RemoteDocument cryptographicSuite) {
        this(attestationPresentation, null, null, policy, cryptographicSuite);
    }

    /**
     * Constructor to validate a document with supplementary validation parameters,
     * a validation policy and cryptographic suite provided
     *
     * @param attestationPresentation {@link RemoteDocument} to validate
     * @param attestationValidationParameters {@link AttestationValidationParametersDTO}
     * @param policy {@link RemoteDocument} validation policy
     * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
     */
    public AttestationToValidateDTO(RemoteDocument attestationPresentation, AttestationValidationParametersDTO attestationValidationParameters,
                                    RemoteDocument policy, RemoteDocument cryptographicSuite) {
        this(attestationPresentation, attestationValidationParameters, null, policy, cryptographicSuite);
    }

    /**
     * Constructor to validate a document with validation time and with a validation policy provided
     *
     * @param attestationPresentation {@link RemoteDocument} to validate
     * @param validationTime {@link Date}
     * @param policy {@link RemoteDocument} validation policy
     */
    public AttestationToValidateDTO(RemoteDocument attestationPresentation, Date validationTime, RemoteDocument policy) {
        this(attestationPresentation, validationTime, policy, null);
    }

    /**
     * Constructor to validate a document with supplementary validation parameters,
     * validation time and with a validation policy provided
     *
     * @param attestationPresentation {@link RemoteDocument} to validate
     * @param attestationValidationParameters {@link AttestationValidationParametersDTO}
     * @param validationTime {@link Date}
     * @param policy {@link RemoteDocument} validation policy
     */
    public AttestationToValidateDTO(RemoteDocument attestationPresentation, AttestationValidationParametersDTO attestationValidationParameters,
                                    Date validationTime, RemoteDocument policy) {
        this(attestationPresentation, attestationValidationParameters, validationTime, policy, null);
    }

    /**
     * Constructor to validate a document with validation time and 
     * with a validation policy and cryptographic suite provided
     *
     * @param attestationPresentation {@link RemoteDocument} to validate
     * @param validationTime {@link Date}
     * @param policy {@link RemoteDocument} validation policy
     * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
     */
    public AttestationToValidateDTO(RemoteDocument attestationPresentation, Date validationTime, RemoteDocument policy,
                                    RemoteDocument cryptographicSuite) {
        this(attestationPresentation, null, validationTime, policy, cryptographicSuite);
    }

    /**
     * Constructor to validate a document with supplementary validation parameters, validation time and
     * with a validation policy and cryptographic suite provided
     *
     * @param attestationPresentation {@link RemoteDocument} to validate
     * @param attestationValidationParameters {@link AttestationValidationParametersDTO}
     * @param validationTime {@link Date}
     * @param policy {@link RemoteDocument} validation policy
     * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
     */
    public AttestationToValidateDTO(RemoteDocument attestationPresentation, AttestationValidationParametersDTO attestationValidationParameters,
                                    Date validationTime, RemoteDocument policy, RemoteDocument cryptographicSuite) {
        this.attestationPresentation = attestationPresentation;
        this.attestationValidationParameters = attestationValidationParameters;
        this.validationTime = validationTime;
        this.policy = policy;
        this.cryptographicSuite = cryptographicSuite;
    }

    /**
     * Gets the Attestation Presentation document
     * 
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getEaaPresentation() {
        return attestationPresentation;
    }

    /**
     * Sets the Attestation Presentation document to be validated
     * 
     * @param attestationPresentation {@link RemoteDocument}
     */
    public void setEaaPresentation(RemoteDocument attestationPresentation) {
        this.attestationPresentation = attestationPresentation;
    }

    /**
     * Gets supplementary input data parameters for Attestation Presentation's validation
     *
     * @return {@link AttestationValidationParametersDTO}
     */
    public AttestationValidationParametersDTO getEaaValidationParameters() {
        return attestationValidationParameters;
    }

    /**
     * Sets supplementary input data for performing an Attestation Presentation's validation, if required
     *
     * @param attestationValidationParameters {@link AttestationValidationParametersDTO}
     */
    public void setEaaValidationParameters(AttestationValidationParametersDTO attestationValidationParameters) {
        this.attestationValidationParameters = attestationValidationParameters;
    }

    /**
     * Gets the validation policy
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getPolicy() {
        return policy;
    }

    /**
     * Sets the validation policy
     *
     * @param policy {@link RemoteDocument}
     */
    public void setPolicy(RemoteDocument policy) {
        this.policy = policy;
    }

    /**
     * Gets a cryptographic suite document (to be applied globally)
     *
     * @return {@link RemoteDocument}
     */
    public RemoteDocument getCryptographicSuite() {
        return cryptographicSuite;
    }

    /**
     * Sets a cryptographic suite document (to be applied globally)
     *
     * @param cryptographicSuite {@link RemoteDocument}
     */
    public void setCryptographicSuite(RemoteDocument cryptographicSuite) {
        this.cryptographicSuite = cryptographicSuite;
    }

    /**
     * Gets the validation time
     *
     * @return {@link Date}
     */
    public Date getValidationTime() {
        return validationTime;
    }

    /**
     * Sets the validation time
     * NOTE: if not defined, the current time is used
     *
     * @param validationTime {@link Date}
     */
    public void setValidationTime(Date validationTime) {
        this.validationTime = validationTime;
    }
    
    /**
     * Gets a token extraction strategy
     *
     * @return {@link TokenExtractionStrategy}
     */
    public TokenExtractionStrategy getTokenExtractionStrategy() {
        return tokenExtractionStrategy;
    }

    /**
     * Sets a token extraction strategy
     *
     * @param tokenExtractionStrategy {@link TokenExtractionStrategy}
     */
    public void setTokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy) {
        this.tokenExtractionStrategy = tokenExtractionStrategy;
    }
    
}
