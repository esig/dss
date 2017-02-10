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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.OID;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.tsl.KeyUsageBit;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * This is the representation of simple (common) CRL source, this is the base
 * class for all real implementations.
 */
public class CRLUtils {

	private static final Logger LOG = LoggerFactory.getLogger(CRLUtils.class);

	/**
	 * This method verifies: the signature of the CRL, the key usage of its
	 * signing certificate and the coherence between the subject names of the
	 * CRL signing certificate and the issuer name of the certificate for which
	 * the verification of the revocation data is carried out. A dedicated
	 * object based on {@code CRLValidity} is created and accordingly updated.
	 *
	 * @param x509CRL
	 *            {@code X509CRL} to be verified (cannot be null)
	 * @param issuerToken
	 *            {@code CertificateToken} used to sign the {@code X509CRL}
	 *            (cannot be null)
	 * @return {@code CRLValidity}
	 */
	public static CRLValidity isValidCRL(final X509CRL x509CRL, final CertificateToken issuerToken) {

		final CRLValidity crlValidity = new CRLValidity();
		crlValidity.setX509CRL(x509CRL);

		try {
			crlValidity.setCrlEncoded(x509CRL.getEncoded());
		} catch (CRLException e) {
			LOG.error("Unable to read the CRL binaries", e);
		}

		final String sigAlgOID = x509CRL.getSigAlgOID();
		crlValidity.setSignatureAlgorithm(SignatureAlgorithm.forOID(sigAlgOID));

		final X500Principal x509CRLIssuerX500Principal = DSSUtils.getNormalizedX500Principal(x509CRL.getIssuerX500Principal());
		final X500Principal issuerTokenSubjectX500Principal = DSSUtils.getNormalizedX500Principal(issuerToken.getSubjectX500Principal());
		if (x509CRLIssuerX500Principal.equals(issuerTokenSubjectX500Principal)) {

			crlValidity.setIssuerX509PrincipalMatches(true);
		}
		crlValidity.setThisUpdate(x509CRL.getThisUpdate());
		crlValidity.setNextUpdate(x509CRL.getNextUpdate());
		crlValidity.setExpiredCertsOnCRL(getExpiredCertsOnCRL(x509CRL));
		checkCriticalExtensions(x509CRL, crlValidity);
		checkSignatureValue(x509CRL, issuerToken, crlValidity);
		if (crlValidity.isSignatureIntact()) {
			crlValidity.setCrlSignKeyUsage(hasCRLSignKeyUsage(issuerToken));
		}
		return crlValidity;
	}

	/**
	 * @return true if the certificate has cRLSign key usage bit set
	 */
	static boolean hasCRLSignKeyUsage(CertificateToken token) {
		return token.checkKeyUsage(KeyUsageBit.crlSign);
	}

	private static void checkSignatureValue(final X509CRL x509CRL, final CertificateToken issuerToken, final CRLValidity crlValidity) {
		try {
			x509CRL.verify(issuerToken.getPublicKey());
			crlValidity.setSignatureIntact(true);
			crlValidity.setIssuerToken(issuerToken);
		} catch (InvalidKeyException e) {
			crlValidity.setSignatureInvalidityReason(e.getClass().getSimpleName() + " - " + e.getMessage());
		} catch (CRLException e) {
			crlValidity.setSignatureInvalidityReason(e.getClass().getSimpleName() + " - " + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			crlValidity.setSignatureInvalidityReason(e.getClass().getSimpleName() + " - " + e.getMessage());
		} catch (SignatureException e) {
			crlValidity.setSignatureInvalidityReason(e.getClass().getSimpleName() + " - " + e.getMessage());
		} catch (NoSuchProviderException e) {
			throw new DSSException(e);
		}
	}

	private static void checkCriticalExtensions(final X509CRL x509CRL, final CRLValidity crlValidity) {
		final Set<String> criticalExtensionOIDs = x509CRL.getCriticalExtensionOIDs();
		if ((criticalExtensionOIDs == null) || (criticalExtensionOIDs.size() == 0)) {
			crlValidity.setUnknownCriticalExtension(false);
		} else {

			byte[] extensionValue = x509CRL.getExtensionValue(Extension.issuingDistributionPoint.getId());
			IssuingDistributionPoint issuingDistributionPoint = IssuingDistributionPoint.getInstance(ASN1OctetString.getInstance(extensionValue).getOctets());
			final boolean onlyAttributeCerts = issuingDistributionPoint.onlyContainsAttributeCerts();
			final boolean onlyCaCerts = issuingDistributionPoint.onlyContainsCACerts();
			final boolean onlyUserCerts = issuingDistributionPoint.onlyContainsUserCerts();
			final boolean indirectCrl = issuingDistributionPoint.isIndirectCRL();
			ReasonFlags onlySomeReasons = issuingDistributionPoint.getOnlySomeReasons();
			DistributionPointName distributionPoint = issuingDistributionPoint.getDistributionPoint();
			boolean urlFound = false;
			if (DistributionPointName.FULL_NAME == distributionPoint.getType()) {
				final GeneralNames generalNames = (GeneralNames) distributionPoint.getName();
				if ((generalNames != null) && (generalNames.getNames() != null) && (generalNames.getNames().length > 0)) {
					for (GeneralName generalName : generalNames.getNames()) {
						if (GeneralName.uniformResourceIdentifier == generalName.getTagNo()) {
							urlFound = true;
						}
					}
				}
			}

			if (!(onlyAttributeCerts && onlyCaCerts && onlyUserCerts && indirectCrl) && (onlySomeReasons == null) && urlFound) {
				crlValidity.setUnknownCriticalExtension(false);
			}
		}
	}

	public static Date getExpiredCertsOnCRL(X509CRL x509crl) {
		Set<String> nonCriticalExtensionOIDs = x509crl.getNonCriticalExtensionOIDs();
		if ((nonCriticalExtensionOIDs != null) && nonCriticalExtensionOIDs.contains(OID.id_ce_expiredCertsOnCRL.getId())) {
			byte[] extensionValue = x509crl.getExtensionValue(OID.id_ce_expiredCertsOnCRL.getId());
			if (Utils.isArrayNotEmpty(extensionValue)) {
				try {
					ASN1OctetString octetString = (ASN1OctetString) ASN1Primitive.fromByteArray(extensionValue);
					ASN1GeneralizedTime generalTime = (ASN1GeneralizedTime) ASN1Primitive.fromByteArray(octetString.getOctets());
					return generalTime.getDate();
				} catch (Exception e) {
					LOG.error("Unable to retrieve id_ce_expiredCertsOnCRL on CRL : " + e.getMessage(), e);
				}
			}
		}
		return null;
	}
}