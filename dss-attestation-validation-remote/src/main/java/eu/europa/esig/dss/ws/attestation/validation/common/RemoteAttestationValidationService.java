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
package eu.europa.esig.dss.ws.attestation.validation.common;

import eu.europa.esig.dss.attestation.common.validation.DefaultAttestationDocumentValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.spi.attestation.AttestationValidationParameters;
import eu.europa.esig.dss.spi.attestation.revocation.AttestationRevocationSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.attestation.AttestationDocumentValidator;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.exception.DSSRemoteServiceException;
import eu.europa.esig.dss.ws.attestation.validation.dto.AttestationToValidateDTO;
import eu.europa.esig.dss.ws.validation.dto.WSReportsDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;

/**
 * Remote service to perform validation of an Electronic Attestation of Attributes
 *
 */
public class RemoteAttestationValidationService {

    private static final Logger LOG = LoggerFactory.getLogger(RemoteAttestationValidationService.class);

    /** The path for default Attestation Presentation policy */
    private static final String EAA_PRESENTATION_POLICY_LOCATION = "/policy/attestation-constraint.xml";

    /** The certificate verifier to use */
    private CertificateVerifier verifier;

    /** The validation policy to be used by default */
    private ValidationPolicy defaultValidationPolicy;

    /** EAA revocation source */
    private AttestationRevocationSource attestationRevocationSource;

    /**
     * Default construction instantiating object with null certificate verifier
     */
    public RemoteAttestationValidationService() {
        // empty
    }

    /**
     * Sets the certificate verifier
     *
     * @param verifier {@link CertificateVerifier}
     */
    public void setVerifier(CertificateVerifier verifier) {
        this.verifier = verifier;
    }

    /**
     * Sets the validation policy to be used by default, when no policy provided within the request
     *
     * @param validationPolicy {@link InputStream}
     */
    public void setDefaultValidationPolicy(InputStream validationPolicy) {
        setDefaultValidationPolicy(validationPolicy, null);
    }

    /**
     * Sets the validation policy with a custom cryptographic suite to be used by default,
     * when no policy provided within the request.
     * If cryptographic suite is set, the constraints from validation policy will be overwritten
     * by the constraints retrieved from the cryptographic suite.
     * When set, the cryptographic suite constraints are applied with the default behavior, using FAIL level.
     * For a customizable cryptographic suite and its applicability context,
     * please use {@code eu.europa.esig.dss.validation.policy.ValidationPolicyLoader}.
     * <p>
     * The format of validation policy should correspond to the DSS XML Validation policy
     * (please include 'dss-policy-jaxb' module in your classpath), unless a custom validation policy has been implemented.
     * The format of cryptographic suite should correspond to XML or JSON schema as defined in ETSI TS 119 322
     * (please include 'dss-policy-crypto-xml' or 'dss-policy-crypto-json' to the classpath), unless a custom
     * cryptographic suite has been implemented.
     * <p>
     * The {@code InputStream} parameters contains the constraint files. If null the default file is used.
     *
     * @param validationPolicy {@link InputStream}
     * @param cryptographicSuite {@link InputStream}
     */
    public void setDefaultValidationPolicy(InputStream validationPolicy, InputStream cryptographicSuite) {
        ValidationPolicyLoader validationPolicyLoader;
        try {
            if (validationPolicy != null) {
                validationPolicyLoader = ValidationPolicyLoader.fromValidationPolicy(validationPolicy);
            } else {
                validationPolicyLoader = ValidationPolicyLoader.fromValidationPolicy(EAA_PRESENTATION_POLICY_LOCATION);
            }
        } catch (Exception e) {
            throw new DSSRemoteServiceException(String.format("Unable to instantiate validation policy: %s", e.getMessage()), e);
        }
        try {
            if (cryptographicSuite != null) {
                validationPolicyLoader = validationPolicyLoader.withCryptographicSuite(cryptographicSuite);
            }
        } catch (Exception e) {
            throw new DSSRemoteServiceException(String.format("Unable to instantiate cryptographic suite: %s", e.getMessage()), e);
        }
        this.defaultValidationPolicy = validationPolicyLoader.create();
    }

    /**
     * Sets the validation policy to be used by default, when no policy provided within the request
     *
     * @param validationPolicy {@link ValidationPolicy}
     */
    public void setDefaultValidationPolicy(ValidationPolicy validationPolicy) {
        this.defaultValidationPolicy = validationPolicy;
    }

    /**
     * Sets a source to request and verify EAA revocation
     *
     * @param attestationRevocationSource {@link AttestationRevocationSource}
     */
    public void setEAARevocationSource(AttestationRevocationSource attestationRevocationSource) {
        this.attestationRevocationSource = attestationRevocationSource;
    }

    /**
     * Validates the Attestation Presentation document
     *
     * @param dataToValidate {@link AttestationToValidateDTO} the request
     * @return {@link WSReportsDTO} response
     */
    public WSReportsDTO validateEAA(AttestationToValidateDTO dataToValidate) {
        LOG.info("ValidateEAA in process...");
        AttestationDocumentValidator validator = initValidator(dataToValidate);

        Reports reports;
        ValidationPolicyLoader validationPolicyLoader;
        RemoteDocument policy = dataToValidate.getPolicy();
        if (policy != null) {
            validationPolicyLoader = ValidationPolicyLoader.fromValidationPolicy(RemoteDocumentConverter.toDSSDocument(policy));
        } else if (defaultValidationPolicy != null) {
            validationPolicyLoader = ValidationPolicyLoader.fromValidationPolicy(defaultValidationPolicy);
        } else {
            validationPolicyLoader = ValidationPolicyLoader.fromValidationPolicy(EAA_PRESENTATION_POLICY_LOCATION);
        }
        RemoteDocument cryptographicSuite = dataToValidate.getCryptographicSuite();
        if (cryptographicSuite != null) {
            validationPolicyLoader.withCryptographicSuite(RemoteDocumentConverter.toDSSDocument(cryptographicSuite));
        }

        ValidationPolicy validationPolicy = validationPolicyLoader.create();
        reports = validator.validateDocument(validationPolicy);

        WSReportsDTO reportsDTO = new WSReportsDTO(reports.getDiagnosticDataJaxb(), reports.getSimpleReportJaxb(),
                reports.getDetailedReportJaxb(), reports.getEtsiValidationReportJaxb());
        LOG.info("ValidateEAA is finished");
        return reportsDTO;
    }

    /**
     * Instantiates a {@code EAAPresentationValidator} based on the request data DTO
     *
     * @param dataToValidate {@link AttestationToValidateDTO} representing the request data
     * @return {@link AttestationDocumentValidator}
     */
    protected AttestationDocumentValidator initValidator(AttestationToValidateDTO dataToValidate) {
        DSSDocument attestationPresentation = RemoteDocumentConverter.toDSSDocument(dataToValidate.getEaaPresentation());
        AttestationDocumentValidator validator = DefaultAttestationDocumentValidator.fromDocument(attestationPresentation);
        if (attestationRevocationSource != null) {
            validator.setEAARevocationSource(attestationRevocationSource);
        }
        if (dataToValidate.getEaaValidationParameters() != null) {
            AttestationValidationParameters attestationValidationParameters =
                    new RemoteAttestationValidationParametersBuilder(dataToValidate.getEaaValidationParameters()).build();
            validator.setEAAValidationParameters(attestationValidationParameters);
        }
        if (dataToValidate.getValidationTime() != null) {
            validator.setValidationTime(dataToValidate.getValidationTime());
        }
        validator.setCertificateVerifier(verifier);
        // If null, uses default (NONE)
        if (dataToValidate.getTokenExtractionStrategy() != null) {
            validator.setTokenExtractionStrategy(dataToValidate.getTokenExtractionStrategy());
        }
        return validator;
    }

}
