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

import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.validation.executor.DocumentProcessExecutor;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.util.Date;
import java.util.List;

/**
 * This is the interface to be used when implementing different signature validators.
 *
 */
public interface DocumentValidator extends ProcessExecutorProvider<DocumentProcessExecutor> {

	/**
	 * Retrieves the signatures found in the document
	 *
	 * @return a list of AdvancedSignatures for validation purposes
	 */
	List<AdvancedSignature> getSignatures();

	/**
	 * Retrieves the detached timestamps found in the document
	 *
	 * @return a list of TimestampToken for validation purposes
	 */
	List<TimestampToken> getDetachedTimestamps();

	/**
	 * Provides a {@code CertificateVerifier} to be used during the validation process.
	 *
	 * @param certVerifier
	 *            {@code CertificateVerifier}
	 */
	void setCertificateVerifier(final CertificateVerifier certVerifier);

	/**
	 * This method allows to set the token extraction strategy to follow in the
	 * diagnostic data generation.
	 * 
	 * @param tokenExtractionStrategy the {@link TokenExtractionStrategy}
	 */
	void setTokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy);

	/**
	 * Sets the TokenIdentifierProvider
	 *
	 * @param identifierProvider {@link TokenIdentifierProvider}
	 */
	void setTokenIdentifierProvider(TokenIdentifierProvider identifierProvider);
	
	/**
	 * This method allows to enable/disable the semantics inclusion in the reports
	 * (Indication / SubIndication meanings)
	 * 
	 * Disabled by default
	 * 
	 * @param include true to enable the inclusion of the semantics
	 */
	void setIncludeSemantics(boolean include);

	/**
	 * Allows to define a custom validation time
	 * 
	 * @param validationTime {@link Date}
	 */
	void setValidationTime(Date validationTime);

	/**
	 * Sets the {@code List} of {@code DSSDocument} containing the original contents to sign, for detached signature
	 * scenarios.
	 *
	 * @param detachedContent
	 *            the {@code List} of {@code DSSDocument} to set
	 */
	void setDetachedContents(final List<DSSDocument> detachedContent);

	/**
	 * Sets the {@code List} of {@code DSSDocument} containing the original container content for ASiC-S signatures.
	 *
	 * @param archiveContents
	 *            the {@code List} of {@code DSSDocument} to set
	 */
	void setContainerContents(final List<DSSDocument> archiveContents);

	/**
	 * Sets a related {@code ManifestFile} to the document to be validated.
	 *
	 * @param manifestFile
	 *            a {@code ManifestFile} to set
	 */
	void setManifestFile(final ManifestFile manifestFile);

	/**
	 * This method allows to define the signing certificate. It is useful in the
	 * case of non AdES signatures.
	 *
	 * @param x509Certificate {@link CertificateToken}
	 * @deprecated use {@link #setSigningCertificateSource(CertificateSource)}
	 */
	@Deprecated
	void defineSigningCertificate(final CertificateToken x509Certificate);

	/**
	 * Set a certificate source which allows to find the signing certificate by kid
	 * or certificate's digest
	 * 
	 * @param certificateSource the certificate source
	 */
	void setSigningCertificateSource(CertificateSource certificateSource);

	/**
	 * This method allows to specify the validation level (Basic / Timestamp /
	 * Long Term / Archival). By default, the selected validation is ARCHIVAL
	 *
	 * @param validationLevel {@link ValidationLevel}
	 */
	void setValidationLevel(ValidationLevel validationLevel);
	
	/**
	 * This method allows to specify if the ETSI Validation Report must be generated.
	 * By default the value if TRUE (the ETSI Validation report will be generated).
	 * 
	 * @param enableEtsiValidationReport - TRUE if the report must be generated, FALSE otherwise
	 */
	void setEnableEtsiValidationReport(boolean enableEtsiValidationReport);
	
	/**
	 * This method allows to set a provider for Signature policies
	 * 
	 * @param signaturePolicyProvider {@link SignaturePolicyProvider}
	 */
	void setSignaturePolicyProvider(SignaturePolicyProvider signaturePolicyProvider);

	/**
	 * Validates the document and all its signatures. The default constraint file is used.
	 *
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument();

	/**
	 * Validates the document and all its signatures. If the validation policy URL is set then the policy constraints
	 * are retrieved from this location. If null or empty the
	 * default file is used.
	 *
	 * @param validationPolicyURL {@link URL}
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument(final URL validationPolicyURL);

	/**
	 * Validates the document and all its signatures. The policyResourcePath specifies the constraint file. If null or
	 * empty the default file is used.
	 *
	 * @param policyResourcePath
	 *            is located against the classpath (getClass().getResourceAsStream), and NOT the filesystem
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument(final String policyResourcePath);

	/**
	 * Validates the document and all its signatures. The {@code File} parameter specifies the constraint file. If null
	 * or empty the default file is used.
	 *
	 * @param policyFile
	 *            contains the validation policy (xml) as {@code File}
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument(final File policyFile);

	/**
	 * Validates the document and all its signatures. The policyDataStream contains the constraint file. If null or
	 * empty the default file is used.
	 *
	 * @param policyDataStream
	 *            contains the validation policy (xml) as {@code InputStream}
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument(final InputStream policyDataStream);

	/**
	 * Validates the document and all its signatures. The {@code validationPolicyJaxb} contains the constraint file. If
	 * null or empty the default file is used.
	 *
	 * @param validationPolicyJaxb
	 *            {@code ConstraintsParameters}
	 * @return {@link Reports}
	 */
	Reports validateDocument(final ConstraintsParameters validationPolicyJaxb);

	/**
	 * Validates the document and all its signatures. The {@code validationPolicy} contains the constraint file. If null
	 * or empty the default file is used.
	 *
	 * @param validationPolicy
	 *            {@code ValidationPolicy}
	 * @return {@link Reports}
	 */
	Reports validateDocument(final ValidationPolicy validationPolicy);

	/**
	 * This method returns the signed document(s) without their signature(s)
	 *
	 * @param signatureId
	 *            the DSS ID of the signature to extract original signer data for
	 * @return list of {@link DSSDocument}s
	 */
	List<DSSDocument> getOriginalDocuments(final String signatureId);

	/**
	 * This method returns the signed document(s) without their signature(s)
	 *
	 * @param advancedSignature
	 *            {@link AdvancedSignature} to find signer documents for
	 * @return list of {@link DSSDocument}s
	 */
	List<DSSDocument> getOriginalDocuments(final AdvancedSignature advancedSignature);
	
	/**
	 * Prepares the {@code validationContext} for signature validation process and
	 * returns a list of signatures to validate
	 * 
	 * @param validationContext
	 *                          {@link ValidationContext}
	 * @param allSignatures
	 *                          a list of all {@link AdvancedSignature}s to be
	 *                          validated
	 */
	void prepareSignatureValidationContext(final ValidationContext validationContext, final List<AdvancedSignature> allSignatures);

	/**
	 * Prepares the {@code validationContext} for a timestamp validation process
	 * 
	 * @param validationContext
	 *                          {@link ValidationContext}
	 * @param timestamps
	 *                          a list of detached timestamps
	 */
	void prepareDetachedTimestampValidationContext(final ValidationContext validationContext, List<TimestampToken> timestamps);

	/**
	 * This method process the signature validation on the given {@code allSignatureList}
	 * 
	 * @param allSignatureList list of {@link AdvancedSignature}s to be validated
	 */
	void processSignaturesValidation(List<AdvancedSignature> allSignatureList);

	/**
	 * Finds SignatureScopes for a list of signatures
	 *
	 * @param currentValidatorSignatures a list of {@link AdvancedSignature}s
	 */
	void findSignatureScopes(List<AdvancedSignature> currentValidatorSignatures);

}
