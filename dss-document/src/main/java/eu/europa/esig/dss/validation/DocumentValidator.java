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

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.util.List;

import org.w3c.dom.Document;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.validation.policy.ProcessExecutor;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.report.Reports;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This is the interface to be used when implementing different signature validators.
 *
 */
public interface DocumentValidator {

	/**
	 * The document to validate, in the case of ASiC container this method returns the signature.
	 *
	 * @return {@code DSSDocument}
	 */
	DSSDocument getDocument();

	/**
	 * This method returns the {@code List} of the signed documents in the case of the detached signatures.
	 *
	 * @return the {@code List} of the detached document {@code DSSDocument}
	 */
	List<DSSDocument> getDetachedContents();

	/**
	 * Retrieves the signatures found in the document
	 *
	 * @return a list of AdvancedSignatures for validation purposes
	 */
	List<AdvancedSignature> getSignatures();

	/**
	 * Provides a {@code CertificateVerifier} to be used during the validation process.
	 *
	 * @param certVerifier {@code CertificateVerifier}
	 */
	void setCertificateVerifier(final CertificateVerifier certVerifier);

	/**
	 * Sets the {@code List} of {@code DSSDocument} containing the original contents to sign, for detached signature scenarios.
	 *
	 * @param detachedContent the {@code List} of {@code DSSDocument} to set
	 */
	void setDetachedContents(final List<DSSDocument> detachedContent);

	/**
	 * This method allows to define the signing certificate. It is useful in the case of ,non AdES signatures.
	 *
	 * @param x509Certificate
	 */
	void defineSigningCertificate(final CertificateToken x509Certificate);

	void setPolicyFile(final File policyDocument);

	void setPolicyFile(final String signatureId, final File policyDocument);

	/**
	 * This method provides the possibility to set the specific {@code ProcessExecutor}
	 *
	 * @param processExecutor
	 */
	void setProcessExecutor(final ProcessExecutor processExecutor);


	/**
	 * Validates the document and all its signatures. The default constraint file is used.
	 *
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument();

	/**
	 * Validates the document and all its signatures. If the validation policy URL is set then the policy constraints are retrieved from this location. If null or empty the
	 * default file is used.
	 *
	 * @param validationPolicyURL
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument(final URL validationPolicyURL);

	/**
	 * Validates the document and all its signatures. The policyResourcePath specifies the constraint file. If null or empty the default file is used.
	 *
	 * @param policyResourcePath is located against the classpath (getClass().getResourceAsStream), and NOT the filesystem
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument(final String policyResourcePath);

	/**
	 * Validates the document and all its signatures. The {@code File} parameter specifies the constraint file. If null or empty the default file is used.
	 *
	 * @param policyFile contains the validation policy (xml) as {@code File}
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument(final File policyFile);

	/**
	 * Validates the document and all its signatures. The policyDataStream contains the constraint file. If null or empty the default file is used.
	 *
	 * @param policyDataStream contains the validation policy (xml) as {@code InputStream}
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument(final InputStream policyDataStream);

	/**
	 * Validates the document and all its signatures. The {@code validationPolicyDom} contains the constraint file. If null or empty the default file is used.
	 *
	 * @param validationPolicyDom {@code Document}
	 * @return
	 */
	Reports validateDocument(final Document validationPolicyDom);

	/**
	 * Validates the document and all its signatures. The {@code validationPolicy} contains the constraint file. If null or empty the default file is used.
	 *
	 * @param validationPolicy {@code ValidationPolicy}
	 * @return
	 */
	Reports validateDocument(final ValidationPolicy validationPolicy);

	/**
	 * This method returns always {@code null} in case of the no ASiC containers.
	 *
	 * @return {@code SignedDocumentValidator} which corresponds to the next signature found within an ASiC-E container. {@code null} if there is no more signatures.
	 */
	DocumentValidator getNextValidator();

	/**
	 * @return
	 */
	DocumentValidator getSubordinatedValidator();

	/**
	 * This method allows the removal of the signature from the given signed document.
	 * - With XAdES signature this operation is only possible for ENVELOPED signatures;
	 * - With ASiC signature this operation is only possible for XAdES kind of container;
	 *
	 * @param signatureId the id of the signature to be removed.
	 * @throws DSSException the exception is thrown when the removal is not possible.
	 */
	DSSDocument removeSignature(final String signatureId) throws DSSException;
}
