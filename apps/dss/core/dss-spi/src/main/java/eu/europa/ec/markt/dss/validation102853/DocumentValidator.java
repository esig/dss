package eu.europa.ec.markt.dss.validation102853;

import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.List;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.validation102853.report.Reports;

/**
 * TODO
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public interface DocumentValidator {

	/**
	 * The document to validate, in the case of ASiC-S container this method returns the signature.
	 *
	 * @return
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
	void defineSigningCertificate(final X509Certificate x509Certificate);

	void setPolicyFile(final File policyDocument);

	void setPolicyFile(final String signatureId, final File policyDocument);

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
	 * TODO (31/07/2014): to be implemented (proposal for v5)
	 * This method allows the removal of the signature from the given signed document.
	 * - With XAdES signature this operation is only possible for ENVELOPED signatures;
	 * - With ASiC signature this operation is only possible for XAdES kind of container;
	 *
	 * @param signatureId the id of the signature to be removed.
	 * @throws DSSException the exception is thrown when the removal is not possible.
	 */
	DSSDocument removeSignature(final String signatureId) throws DSSException;
}
