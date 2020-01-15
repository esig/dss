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
import java.util.Date;

import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.validation.executor.DocumentProcessExecutor;
import eu.europa.esig.dss.validation.executor.ValidationLevel;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * This is the interface to be used when implementing different signature validators.
 *
 */
public interface DocumentValidator extends ProcessExecutorProvider<DocumentProcessExecutor> {
	
	/**
	 * Provides a {@code CertificateVerifier} to be used during the validation process.
	 *
	 * @param certVerifier
	 *            {@code CertificateVerifier}
	 */
	void setCertificateVerifier(final CertificateVerifier certVerifier);
	
	/**
	 * Allows to define a custom validation time
	 * 
	 * @param validationTime {@link Date}
	 */
	void setValidationTime(Date validationTime);

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
	 * Validates the document and all its signatures. The default constraint file is
	 * used.
	 *
	 * @return {@code Reports}: diagnostic data, detailed report and simple report
	 */
	Reports validateDocument();

	/**
	 * Validates the document and all its signatures. If the validation policy URL is set then the policy constraints
	 * are retrieved from this location. If null or empty the
	 * default file is used.
	 *
	 * @param validationPolicyURL
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
	 * @return
	 */
	Reports validateDocument(final ConstraintsParameters validationPolicyJaxb);

	/**
	 * Validates the document and all its signatures. The {@code validationPolicy} contains the constraint file. If null
	 * or empty the default file is used.
	 *
	 * @param validationPolicy
	 *            {@code ValidationPolicy}
	 * @return
	 */
	Reports validateDocument(final ValidationPolicy validationPolicy);

}
