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
package eu.europa.esig.dss.validation.reports.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;

import java.util.Date;
import java.util.Set;

/**
 * Builds the DiagnosticData for a CertificateToken validation
 */
public class CertificateDiagnosticDataBuilder extends DiagnosticDataBuilder {

	/**
	 * Default constructor
	 */
	public CertificateDiagnosticDataBuilder() {
		// empty
	}

	/**
	 * Builds {@code XmlDiagnosticData}
	 *
	 * @return {@link XmlDiagnosticData}
	 */
	@Override
	public XmlDiagnosticData build() {
		XmlDiagnosticData diagnosticData = super.build();

		diagnosticData.setOrphanTokens(buildXmlOrphanTokens());

		return diagnosticData;
	}

	@Override
	public CertificateDiagnosticDataBuilder usedCertificates(Set<CertificateToken> usedCertificates) {
		return (CertificateDiagnosticDataBuilder) super.usedCertificates(usedCertificates);
	}

	@Override
	public CertificateDiagnosticDataBuilder usedRevocations(Set<RevocationToken<?>> usedRevocations) {
		return (CertificateDiagnosticDataBuilder) super.usedRevocations(usedRevocations);
	}

	@Override
	public CertificateDiagnosticDataBuilder allCertificateSources(ListCertificateSource trustedCertSources) {
		return (CertificateDiagnosticDataBuilder) super.allCertificateSources(trustedCertSources);
	}

	@Override
	public CertificateDiagnosticDataBuilder validationDate(Date validationDate) {
		return (CertificateDiagnosticDataBuilder) super.validationDate(validationDate);
	}

	@Override
	public CertificateDiagnosticDataBuilder tokenExtractionStrategy(TokenExtractionStrategy tokenExtractionStrategy) {
		return (CertificateDiagnosticDataBuilder) super.tokenExtractionStrategy(tokenExtractionStrategy);
	}

	@Override
	public CertificateDiagnosticDataBuilder defaultDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
		return (CertificateDiagnosticDataBuilder) super.defaultDigestAlgorithm(digestAlgorithm);
	}

}
