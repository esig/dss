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
package eu.europa.esig.dss.ws.cert.validation.dto;

import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.Date;
import java.util.List;

/**
 * The DTO representing the certificate validation request
 */
public class CertificateToValidateDTO {
	
	/**
	 * The certificate to be validated.
	 */
	private RemoteCertificate certificate;
	
	/**
	 * Allows to specify missing certificates in the chain.
	 * <p>
	 * OPTIONAL.
	 */
	private List<RemoteCertificate> certificateChain;
	
	/**
	 * Allows to specify a validation time different from the current time.
	 * <p>
	 * OPTIONAL.
	 */
	private Date validationTime;

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
	 * Allows to specify the token extraction to follow
	 * <p>
	 * NONE by default
	 */
	private TokenExtractionStrategy tokenExtractionStrategy = TokenExtractionStrategy.NONE;

	/**
	 * The empty constructor
	 */
	public CertificateToValidateDTO() {
		// empty
	}

	/**
	 * The constructor with a certificate to be validated
	 *
	 * @param certificate {@link RemoteCertificate} to be validated
	 */
	public CertificateToValidateDTO(RemoteCertificate certificate) {
		this(certificate, null, null);
	}

	/**
	 * The default constructor
	 *
	 * @param certificate {@link RemoteCertificate} to be validated
	 * @param certificateChain a list of {@link RemoteCertificate}s representing the certificate chain
	 * @param validationTime {@link Date} the validation time
	 */
	public CertificateToValidateDTO(RemoteCertificate certificate, List<RemoteCertificate> certificateChain, Date validationTime) {
		this(certificate, certificateChain, validationTime, null);
	}

	/**
	 * The default constructor with a token extraction strategy
	 *
	 * @param certificate {@link RemoteCertificate} to be validated
	 * @param certificateChain a list of {@link RemoteCertificate}s representing the certificate chain
	 * @param validationTime {@link Date} the validation time
	 * @param tokenExtractionStrategy {@link TokenExtractionStrategy} for the DiagnosticData report
	 */
	public CertificateToValidateDTO(RemoteCertificate certificate, List<RemoteCertificate> certificateChain,
									Date validationTime, TokenExtractionStrategy tokenExtractionStrategy) {
		this(certificate, certificateChain, validationTime, null, tokenExtractionStrategy);
	}

	/**
	 * The default constructor with a custom validation policy
	 *
	 * @param certificate {@link RemoteCertificate} to be validated
	 * @param certificateChain a list of {@link RemoteCertificate}s representing the certificate chain
	 * @param validationTime {@link Date} the validation time
	 * @param policy {@link RemoteDocument}
	 * @param tokenExtractionStrategy {@link TokenExtractionStrategy} for the DiagnosticData report
	 */
	public CertificateToValidateDTO(RemoteCertificate certificate, List<RemoteCertificate> certificateChain,
			Date validationTime, RemoteDocument policy, TokenExtractionStrategy tokenExtractionStrategy) {
		this(certificate, certificateChain, validationTime, policy, null, tokenExtractionStrategy);
	}

	/**
	 * The default constructor with a custom validation policy
	 *
	 * @param certificate {@link RemoteCertificate} to be validated
	 * @param certificateChain a list of {@link RemoteCertificate}s representing the certificate chain
	 * @param validationTime {@link Date} the validation time
	 * @param policy {@link RemoteDocument}
	 * @param cryptographicSuite {@link RemoteDocument} cryptographic suite
	 * @param tokenExtractionStrategy {@link TokenExtractionStrategy} for the DiagnosticData report
	 */
	public CertificateToValidateDTO(RemoteCertificate certificate, List<RemoteCertificate> certificateChain,
									Date validationTime, RemoteDocument policy, RemoteDocument cryptographicSuite,
									TokenExtractionStrategy tokenExtractionStrategy) {
		this.certificate = certificate;
		this.certificateChain = certificateChain;
		this.validationTime = validationTime;
		this.policy = policy;
		this.cryptographicSuite = cryptographicSuite;
		this.tokenExtractionStrategy = tokenExtractionStrategy;
	}

	/**
	 * Gets the certificate to be validated
	 *
	 * @return {@link RemoteCertificate}
	 */
	public RemoteCertificate getCertificate() {
		return certificate;
	}

	/**
	 * Sets the certificate to be validated
	 *
	 * @param certificate {@link RemoteCertificate}
	 */
	public void setCertificate(RemoteCertificate certificate) {
		this.certificate = certificate;
	}

	/**
	 * Gets the certificate chain for the certificate to be validated
	 *
	 * @return a list of {@link RemoteCertificate}s representing the certificate chain
	 */
	public List<RemoteCertificate> getCertificateChain() {
		return certificateChain;
	}

	/**
	 * Sets the certificate chain for the certificate to be validated
	 *
	 * @param certificateChain  list of {@link RemoteCertificate}s representing the certificate chain
	 */
	public void setCertificateChain(List<RemoteCertificate> certificateChain) {
		this.certificateChain = certificateChain;
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
	 *
	 * @param validationTime {@link Date}
	 */
	public void setValidationTime(Date validationTime) {
		this.validationTime = validationTime;
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
	 * Gets the token extraction strategy
	 *
	 * @return {@link TokenExtractionStrategy}
	 */
	public TokenExtractionStrategy getTokenExtractionStrategy() {
		return tokenExtractionStrategy;
	}

	/**
	 * Sets the token extraction strategy for DiagnosticData
	 *
	 * @param tokenExtractionStrategy {@link TokenExtractionStrategy}
	 */
	public void setTokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy) {
		this.tokenExtractionStrategy = tokenExtractionStrategy;
	}

}
