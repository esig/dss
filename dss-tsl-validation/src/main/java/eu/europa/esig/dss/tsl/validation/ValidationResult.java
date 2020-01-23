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
package eu.europa.esig.dss.tsl.validation;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.tsl.cache.CachedResult;

public class ValidationResult implements CachedResult {
	
	private final Indication indication;
	private final SubIndication subIndication;
	private final Date signingTime;
	private final CertificateToken signingCertificate;
	private final CertificateSource certificateSource;

	public ValidationResult(Indication indication, SubIndication subIndication, Date signingTime, 
			CertificateToken signingCertificate, CertificateSource certificateSource) {
		this.indication = indication;
		this.subIndication = subIndication;
		this.signingTime = signingTime;
		this.signingCertificate = signingCertificate;
		this.certificateSource = certificateSource;
	}
	
	public Indication getIndication() {
		return indication;
	}

	public SubIndication getSubIndication() {
		return subIndication;
	}

	public Date getSigningTime() {
		return signingTime;
	}

	public CertificateToken getSigningCertificate() {
		return signingCertificate;
	}
	
	public List<CertificateToken> getPotentialSigners() {
		return new ArrayList<>(certificateSource.getCertificates());
	}

}
