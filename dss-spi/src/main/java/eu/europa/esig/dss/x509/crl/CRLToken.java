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
package eu.europa.esig.dss.x509.crl;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSNotApplicableMethodException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.TokenValidationExtraInfo;

/**
 * This class represents a CRL and provides the information about its validity.
 */
public class CRLToken extends RevocationToken {

	private static final Logger LOG = LoggerFactory.getLogger(CRLToken.class);

	/**
	 * The reference to the related {@code CRLValidity}
	 */
	private final CRLValidity crlValidity;

	/**
	 * The constructor to be used with the certificate which is managed by the
	 * CRL and the {@code CRLValidity}.
	 *
	 * @param certificateToken
	 *            the {@code CertificateToken} which is managed by this CRL.
	 * @param crlValidity
	 *            {@code CRLValidity} containing the information about the
	 *            validity of the CRL
	 */
	public CRLToken(final CertificateToken certificateToken, final CRLValidity crlValidity) {
		if (crlValidity == null) {
			throw new NullPointerException();
		}
		this.crlValidity = crlValidity;
		copyCommonValuesFromCRL();
		setRevocationStatus(certificateToken);
		LOG.debug("+CRLToken");
	}

	private void copyCommonValuesFromCRL() {
		this.signatureAlgorithm = crlValidity.getSignatureAlgorithm();
		this.thisUpdate = crlValidity.getThisUpdate();
		this.productionDate = crlValidity.getThisUpdate(); // dates are equals in case of CRL
		this.nextUpdate = crlValidity.getNextUpdate();
		this.expiredCertsOnCRL = crlValidity.getExpiredCertsOnCRL();

		if (crlValidity.getIssuerToken() != null) { // if the signature is invalid, the issuer is null
			this.issuerToken = crlValidity.getIssuerToken();
			this.issuerX500Principal = crlValidity.getIssuerToken().getSubjectX500Principal();
		}

		this.extraInfo = new TokenValidationExtraInfo();

		this.signatureValid = crlValidity.isSignatureIntact();
		this.signatureInvalidityReason = crlValidity.getSignatureInvalidityReason();
	}

	/**
	 * @param certificateToken
	 *            the {@code CertificateToken} which is managed by this CRL.
	 */
	private void setRevocationStatus(final CertificateToken certificateToken) {
		final CertificateToken issuerToken = certificateToken.getIssuerToken();
		if (!issuerToken.equals(crlValidity.getIssuerToken())) {
			if (!crlValidity.isSignatureIntact()) {
				throw new DSSException(crlValidity.getSignatureInvalidityReason());
			}
			throw new DSSException("The CRLToken is not signed by the same issuer as the CertificateToken to be verified!");
		}

		final BigInteger serialNumber = certificateToken.getSerialNumber();
		final X509CRL x509crl = crlValidity.getX509CRL();
		final X509CRLEntry crlEntry = x509crl.getRevokedCertificate(serialNumber);
		status = null == crlEntry;
		if (!status) {
			revocationDate = crlEntry.getRevocationDate();
			reason = DSSRevocationUtils.getRevocationReason(crlEntry);
		}
	}

	/**
	 * @return the x509crl
	 */
	public X509CRL getX509crl() {
		return crlValidity.getX509CRL();
	}

	@Override
	public boolean isSignedBy(final CertificateToken issuerToken) {
		throw new DSSNotApplicableMethodException(this.getClass());
	}

	public CRLValidity getCrlValidity() {
		return crlValidity;
	}

	/**
	 * This method returns the DSS abbreviation of the CRLToken. It is used for
	 * debugging purpose.
	 *
	 * @return the DSS abbreviation of the CRLToken
	 */
	@Override
	public String getAbbreviation() {
		return "CRLToken[" + (productionDate == null ? "?" : DSSUtils.formatInternal(productionDate)) + ", signedBy="
				+ (issuerToken == null ? "?" : issuerToken.getDSSIdAsString()) + "]";
	}

	@Override
	public byte[] getEncoded() {
		return crlValidity.getCrlEncoded();
	}

	/**
	 * Indicates if the token signature is intact and the signing certificate
	 * has cRLSign key usage bit set.
	 *
	 * @return {@code true} or {@code false}
	 */
	@Override
	public boolean isValid() {
		return crlValidity.isValid();
	}

	@Override
	public String toString(String indentStr) {
		try {
			StringBuilder out = new StringBuilder();
			out.append(indentStr).append("CRLToken[\n");
			indentStr += "\t";
			out.append(indentStr).append("Production time: ").append(productionDate == null ? "?" : DSSUtils.formatInternal(productionDate)).append('\n');
			out.append(indentStr).append("Signature algorithm: ").append(signatureAlgorithm == null ? "?" : signatureAlgorithm).append('\n');
			out.append(indentStr).append("Status: ").append(getStatus()).append('\n');
			if (issuerToken != null) {
				out.append(indentStr).append("Issuer's certificate: ").append(issuerToken.getDSSIdAsString()).append('\n');
			}
			List<String> validationExtraInfo = extraInfo.getValidationInfo();
			if (validationExtraInfo.size() > 0) {

				for (String info : validationExtraInfo) {

					out.append('\n').append(indentStr).append("\t- ").append(info);
				}
				out.append('\n');
			}
			indentStr = indentStr.substring(1);
			out.append(indentStr).append("]");
			return out.toString();
		} catch (Exception e) {
			return ((Object) this).toString();
		}
	}
}
