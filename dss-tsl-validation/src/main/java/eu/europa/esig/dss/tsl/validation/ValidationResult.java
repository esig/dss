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
package eu.europa.esig.dss.tsl.validation;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.CachedResult;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * The validation task result
 */
public class ValidationResult implements CachedResult {

	/** The used certificate source */
	private final CertificateSource certificateSource;

	/** The validation Indication */
	private Indication indication;

	/** The validation SubIndication */
	private SubIndication subIndication;

	/** The claimed signing time */
	private Date signingTime;

	/** The signing certificate */
	private CertificateToken signingCertificate;

	/**
	 * Default constructor
	 *
	 * @param indication {@link Indication}
	 * @param subIndication {@link SubIndication}
	 * @param signingTime {@link Date}
	 * @param signingCertificate {@link CertificateSource}
	 * @param certificateSource {@link Indication}
	 */
	public ValidationResult(Indication indication, SubIndication subIndication, Date signingTime, 
			CertificateToken signingCertificate, CertificateSource certificateSource) {
		this.indication = indication;
		this.subIndication = subIndication;
		this.signingTime = signingTime;
		this.signingCertificate = signingCertificate;
		this.certificateSource = certificateSource;
	}

	/**
	 * Gets validation Indication
	 *
	 * @return {@link Indication}
	 */
	public Indication getIndication() {
		return indication;
	}

	/**
	 * Gets validation SubIndication
	 *
	 * @return {@link SubIndication}
	 */
	public SubIndication getSubIndication() {
		return subIndication;
	}

	/**
	 * Gets the (claimed) signing time
	 *
	 * @return {@link Date}
	 */
	public Date getSigningTime() {
		return signingTime;
	}

	/**
	 * Gets the signing certificate
	 *
	 * @return {@link CertificateToken}
	 */
	public CertificateToken getSigningCertificate() {
		return signingCertificate;
	}

	/**
	 * Gets a list of signing candidates
	 *
	 * @return a list of {@link CertificateToken}s
	 */
	public List<CertificateToken> getPotentialSigners() {
		return new ArrayList<>(certificateSource.getCertificates());
	}

}
