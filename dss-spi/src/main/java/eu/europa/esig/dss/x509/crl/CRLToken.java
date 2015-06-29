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
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.cert.X509CRLHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSNotApplicableMethodException;
import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.SignatureAlgorithm;
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
	 * The Url which was used to obtain the CRL.
	 */
	private String sourceURL;

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

		ensureNotNull(crlValidity);
		this.crlValidity = crlValidity;
		setDefaultValues();
		setRevocationStatus(certificateToken);
		LOG.debug("+CRLToken");
	}

	private void ensureNotNull(final CRLValidity crlValidity) {

		if (crlValidity == null) {
			throw new NullPointerException();
		}
		if (crlValidity.getX509CRL() == null) {
			throw new NullPointerException();
		}
	}

	private void setDefaultValues() {

		final X509CRL x509crl = crlValidity.getX509CRL();
		final String sigAlgOID = x509crl.getSigAlgOID();
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.forOID(sigAlgOID);
		this.algorithmUsedToSignToken = signatureAlgorithm;
		this.issuingTime = x509crl.getThisUpdate();
		this.nextUpdate = x509crl.getNextUpdate();
		issuerX500Principal = x509crl.getIssuerX500Principal();
		this.extraInfo = new TokenValidationExtraInfo();

		issuerToken = crlValidity.getIssuerToken();
		signatureValid = crlValidity.isSignatureIntact();
		signatureInvalidityReason = crlValidity.getSignatureInvalidityReason();
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

			final String revocationReason = DSSRevocationUtils.getRevocationReason(crlEntry);
			reason = revocationReason;
		}
	}

	/**
	 * @return the x509crl
	 */
	public X509CRL getX509crl() {
		return crlValidity.getX509CRL();
	}

	/**
	 * @return the a copy of x509crl as a X509CRLHolder
	 */
	public X509CRLHolder getX509CrlHolder() {

		try {

			final X509CRL x509crl = getX509crl();
			final TBSCertList tbsCertList = TBSCertList.getInstance(x509crl.getTBSCertList());
			final AlgorithmIdentifier sigAlgOID = new AlgorithmIdentifier(new ASN1ObjectIdentifier(x509crl.getSigAlgOID()));
			final byte[] signature = x509crl.getSignature();
			final DERSequence seq = new DERSequence(new ASN1Encodable[] { tbsCertList, sigAlgOID, new DERBitString(signature) });
			final CertificateList x509CRL = new CertificateList(seq);
			// final CertificateList x509CRL = new
			// CertificateList.getInstance((Object)seq);
			final X509CRLHolder x509crlHolder = new X509CRLHolder(x509CRL);
			return x509crlHolder;
		} catch (CRLException e) {
			throw new DSSException(e);
		}
	}

	@Override
	public String getSourceURL() {

		return sourceURL;
	}

	/**
	 * This sets the revocation data source URL. It is only used in case of
	 * {@code OnlineCRLSource}.
	 *
	 * @param sourceURL
	 *            the URL which was used to retrieve this CRL
	 */
	public void setSourceURL(final String sourceURL) {

		this.sourceURL = sourceURL;
	}

	@Override
	public boolean isSignedBy(final CertificateToken issuerToken) {
		throw new DSSNotApplicableMethodException(this.getClass());
	}

	/**
	 * This method returns the DSS abbreviation of the CRLToken. It is used for
	 * debugging purpose.
	 *
	 * @return the DSS abbreviation of the CRLToken
	 */
	@Override
	public String getAbbreviation() {

		return "CRLToken[" + (issuingTime == null ? "?" : DSSUtils.formatInternal(issuingTime)) + ", signedBy="
				+ (issuerToken == null ? "?" : issuerToken.getDSSIdAsString()) + "]";
	}

	@Override
	public byte[] getEncoded() {
		try {
			return crlValidity.getX509CRL().getEncoded();
		} catch (CRLException e) {
			throw new DSSException("CRL encoding error: " + e.getMessage(), e);
		}
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

	/**
	 * Gets the thisUpdate date from the CRL.
	 *
	 * @return the thisUpdate date from the CRL.
	 */
	public Date getThisUpdate() {
		return crlValidity.getX509CRL().getThisUpdate();
	}

	@Override
	public String toString(String indentStr) {

		try {

			StringBuilder out = new StringBuilder();
			out.append(indentStr).append("CRLToken[\n");
			indentStr += "\t";
			out.append(indentStr).append("Version: ").append(crlValidity.getX509CRL().getVersion()).append('\n');
			out.append(indentStr).append("Issuing time: ").append(issuingTime == null ? "?" : DSSUtils.formatInternal(issuingTime)).append('\n');
			out.append(indentStr).append("Signature algorithm: ").append(algorithmUsedToSignToken == null ? "?" : algorithmUsedToSignToken)
			.append('\n');
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
