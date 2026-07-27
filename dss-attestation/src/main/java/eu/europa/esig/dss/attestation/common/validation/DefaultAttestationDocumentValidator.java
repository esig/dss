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
package eu.europa.esig.dss.attestation.common.validation;

import eu.europa.esig.dss.enumerations.ValidationLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.attestation.AttestationPresentation;
import eu.europa.esig.dss.spi.attestation.AttestationValidationParameters;
import eu.europa.esig.dss.spi.attestation.revocation.AttestationRevocationSource;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.attestation.AttestationDocumentValidator;
import eu.europa.esig.dss.validation.executor.DocumentProcessExecutor;
import eu.europa.esig.dss.validation.executor.attestation.AttestationProcessExecutor;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.reports.diagnostic.SignedDocumentDiagnosticDataBuilder;
import eu.europa.esig.dss.validation.reports.diagnostic.XmlDiagnosticDataFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;
import java.util.ServiceLoader;

/**
 * This class is used to perform a validation of an attestation presentation document (EAA, PID, etc.)
 * <p>
 * In order to perform validation-process, please ensure the `dss-validation` module is loaded
 * within the dependencies list of your project.
 *
 */
public abstract class DefaultAttestationDocumentValidator extends SignedDocumentValidator implements AttestationDocumentValidator {

    private static final Logger LOG = LoggerFactory.getLogger(DefaultAttestationDocumentValidator.class);

    /** The path for default Attestation Presentation policy (EAA based) */
    private static final String ATTESTATION_POLICY_LOCATION = "/policy/eaa-constraint.xml";

    /**
     * Empty constructor
     *
     * @param attestationDocumentAnalyzer {@link DefaultAttestationDocumentAnalyzer}
     */
    protected DefaultAttestationDocumentValidator(final DefaultAttestationDocumentAnalyzer attestationDocumentAnalyzer) {
        super(attestationDocumentAnalyzer);
    }

    @Override
    public DefaultAttestationDocumentAnalyzer getDocumentAnalyzer() {
        return (DefaultAttestationDocumentAnalyzer) super.getDocumentAnalyzer();
    }

    /**
     * This method guesses the document format and returns an appropriate Attestation Presentation validator.
     *
     * @param dssDocument
     *            The instance of {@code DSSDocument} to validate
     * @return returns the specific instance of {@link DefaultAttestationDocumentValidator} in terms of the document type
     */
    public static DefaultAttestationDocumentValidator fromDocument(final DSSDocument dssDocument) {
        Objects.requireNonNull(dssDocument, "DSSDocument is null");
        ServiceLoader<AttestationDocumentValidatorFactory> serviceLoaders = ServiceLoader.load(AttestationDocumentValidatorFactory.class);
        for (AttestationDocumentValidatorFactory factory : serviceLoaders) {
            if (factory.isSupported(dssDocument)) {
                return factory.create(dssDocument);
            }
        }
        throw new UnsupportedOperationException("Document format not recognized/handled");
    }

    @Override
    public void setAttestationRevocationSource(AttestationRevocationSource attestationRevocationSource) {
        getDocumentAnalyzer().setAttestationRevocationSource(attestationRevocationSource);
    }

    @Override
    public void setAttestationValidationParameters(AttestationValidationParameters attestationValidationParameters) {
        getDocumentAnalyzer().setAttestationValidationParameters(attestationValidationParameters);
    }

    @Override
    public AttestationPresentation getAttestationPresentation() {
        return getDocumentAnalyzer().getAttestationPresentation();
    }

    @Override
    public DocumentProcessExecutor getDefaultProcessExecutor() {
        return new AttestationProcessExecutor();
    }

    @Override
    protected ValidationPolicyLoader fromDefaultValidationPolicyLoader() {
        return ValidationPolicyLoader.fromValidationPolicy(
                DefaultAttestationDocumentValidator.class.getResourceAsStream(ATTESTATION_POLICY_LOCATION));
    }

    @Override
    public AttestationDocumentDiagnosticDataBuilder initializeDiagnosticDataBuilder() {
        return new AttestationDocumentDiagnosticDataBuilder()
                .setSignatureDiagnosticDataBuilder(getSignatureDiagnosticDataBuilder());
    }

    @Override
    protected XmlDiagnosticDataFactory initDiagnosticDataFactory(SignedDocumentDiagnosticDataBuilder diagnosticDataBuilder) {
        return new XmlAttestationDocumentDiagnosticDataFactory((AttestationDocumentDiagnosticDataBuilder) diagnosticDataBuilder);
    }

    @Override
    public void setValidationLevel(ValidationLevel validationLevel) {
        LOG.info("#setValidationLevel method is not supported within the AttestationPresentationValidator class! " +
                "The validation always corresponds to the BASIC_SIGNATURES level.");
    }

    /**
     * This method returns a signature format specific {@code DiagnosticDataBuilder}
     *
     * @return {@link SignedDocumentDiagnosticDataBuilder}
     */
    protected abstract SignedDocumentDiagnosticDataBuilder getSignatureDiagnosticDataBuilder();

    @Override
    public List<DSSDocument> getOriginalDocuments(AdvancedSignature advancedSignature) {
        throw new UnsupportedOperationException("#getOriginalDocuments(AdvancedSignature) is " +
                "not supported for AttestationPresentationValidator!");
    }

}
