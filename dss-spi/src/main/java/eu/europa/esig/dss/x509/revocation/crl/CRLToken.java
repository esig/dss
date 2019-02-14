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
package eu.europa.esig.dss.x509.revocation.crl;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.CRLReason;
import java.security.cert.X509CRLEntry;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationToken;
import eu.europa.esig.dss.x509.crl.CRLReasonEnum;

/**
 * This class represents a CRL and provides the information about its validity.
 */
public class CRLToken extends RevocationToken {

	private static final long serialVersionUID = 1934492191629483078L;

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
		initInfo();
		setRevocationStatus(certificateToken);
		LOG.debug("+CRLToken");
	}

	@Override
	public void initInfo() {
		this.revocationTokenKey = crlValidity.getKey();
		this.signatureAlgorithm = crlValidity.getSignatureAlgorithm();
		this.thisUpdate = crlValidity.getThisUpdate();
		this.productionDate = crlValidity.getThisUpdate(); // dates are equals in case of CRL
		this.nextUpdate = crlValidity.getNextUpdate();
		this.expiredCertsOnCRL = crlValidity.getExpiredCertsOnCRL();

		CertificateToken issuerToken = crlValidity.getIssuerToken();
		if (issuerToken != null) {
			this.publicKeyOfTheSigner = issuerToken.getPublicKey();
		}

		this.signatureValid = crlValidity.isSignatureIntact();
		this.signatureInvalidityReason = crlValidity.getSignatureInvalidityReason();
	}

	/**
	 * @param certificateToken
	 *            the {@code CertificateToken} which is managed by this CRL.
	 */
	private void setRevocationStatus(final CertificateToken certificateToken) {
		final X500Principal issuerToken = certificateToken.getIssuerX500Principal();
		CertificateToken crlSigner = crlValidity.getIssuerToken();
		X500Principal crlSignerSubject = null;
		if (crlSigner != null) {
			crlSignerSubject = crlSigner.getSubjectX500Principal();
		}

		if (!DSSUtils.x500PrincipalAreEquals(issuerToken, crlSignerSubject)) {
			if (!crlValidity.isSignatureIntact()) {
				throw new DSSException(crlValidity.getSignatureInvalidityReason());
			}
			throw new DSSException("The CRLToken is not signed by the same issuer as the CertificateToken to be verified!");
		}

		final BigInteger serialNumber = certificateToken.getSerialNumber();
		X509CRLEntry crlEntry = CRLUtils.getRevocationInfo(crlValidity, serialNumber);

		status = null == crlEntry;
		if (!status) {
			revocationDate = crlEntry.getRevocationDate();
			CRLReason revocationReason = crlEntry.getRevocationReason();
			if (revocationReason != null) {
				reason = CRLReasonEnum.fromInt(revocationReason.ordinal());
			}
		}
	}

	@Override
	protected boolean checkIsSignedBy(final CertificateToken token) {
		throw new UnsupportedOperationException(this.getClass().getName());
	}

	public CRLValidity getCrlValidity() {
		return crlValidity;
	}

	@Override
	public X500Principal getIssuerX500Principal() {
		if (crlValidity.getIssuerToken() != null) { // if the signature is invalid, the issuer is null
		return crlValidity.getIssuerToken().getSubjectX500Principal();
		} else {
			return null;
		}
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
				+ getIssuerX500Principal() + "]";
	}

	@Override
	public byte[] getEncoded() {
		return crlValidity.getCrlEncoded();
	}

	public InputStream getCRLStream() {
		return crlValidity.getCrlInputStream();
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
		StringBuilder out = new StringBuilder();
		out.append(indentStr).append("CRLToken[\n");
		indentStr += "\t";
		out.append(indentStr).append("Production time: ").append(productionDate == null ? "?" : DSSUtils.formatInternal(productionDate)).append('\n');
		out.append(indentStr).append("Signature algorithm: ").append(signatureAlgorithm == null ? "?" : signatureAlgorithm).append('\n');
		out.append(indentStr).append("Status: ").append(getStatus()).append('\n');
		out.append(indentStr).append("Issuer's certificate: ").append(getIssuerX500Principal()).append('\n');
		indentStr = indentStr.substring(1);
		out.append(indentStr).append(']');
		return out.toString();
	}

}
