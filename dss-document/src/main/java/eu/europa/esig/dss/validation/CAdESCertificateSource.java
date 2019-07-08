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

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificate;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificateV2;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.CertificateRef;
import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.Digest;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 * CertificateSource that retrieves items from a CAdES Signature
 */
@SuppressWarnings("serial")
public class CAdESCertificateSource extends CMSCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESCertificateSource.class);

	private transient final CMSSignedData cmsSignedData;
	private transient final AttributeTable signedAttributes;

	/**
	 * Cached values
	 */
	private List<CertificateToken> keyInfoCertificates;
	private List<CertificateRef> signingCertificateValues;

	/**
	 * The constructor with additional signer id parameter. All certificates are
	 * extracted during instantiation.
	 *
	 * @param cmsSignedData {@link CMSSignedData} of the signature
	 * @param certPool {@link CertificatePool} is being used
	 */
	public CAdESCertificateSource(final CMSSignedData cmsSignedData, final CertificatePool certPool) {
		this(cmsSignedData, DSSASN1Utils.getFirstSignerInformation(cmsSignedData), certPool);
	}

	/**
	 * The constructor with additional signer id parameter. All certificates are
	 * extracted during instantiation.
	 *
	 * @param cmsSignedData {@link CMSSignedData} of the signature
	 * @param signerInformation {@link SignerInformation}
	 * @param certPool {@link CertificatePool} is being used
	 */
	public CAdESCertificateSource(final CMSSignedData cmsSignedData, SignerInformation signerInformation, final CertificatePool certPool) {
		super(signerInformation.getUnsignedAttributes(), certPool);
		Objects.requireNonNull(cmsSignedData, "CMS SignedData is null, it must be provided!");
		Objects.requireNonNull(signerInformation, "SignerInformation is null, it must be provided!");
		this.cmsSignedData = cmsSignedData;
		this.signedAttributes = signerInformation.getSignedAttributes();

		// Init CertPool
		getKeyInfoCertificates();
		getCertificateValues();
	}

	@Override
	public List<CertificateToken> getKeyInfoCertificates() {
		if (keyInfoCertificates == null) {
			keyInfoCertificates = new ArrayList<CertificateToken>();
			try {
				final Collection<X509CertificateHolder> x509CertificateHolders = cmsSignedData.getCertificates().getMatches(null);
				for (final X509CertificateHolder x509CertificateHolder : x509CertificateHolders) {
					final CertificateToken certificateToken = addCertificate(DSSASN1Utils.getCertificate(x509CertificateHolder));
					if (!keyInfoCertificates.contains(certificateToken)) {
						keyInfoCertificates.add(certificateToken);
					}
				}
			} catch (Exception e) {
				LOG.warn("Cannot extract certificates from CMS Signed Data : {}", e.getMessage());
			}
		}
		return keyInfoCertificates;
	}

	@Override
	public List<CertificateToken> getAttrAuthoritiesCertValues() {
		// Not applicable for CAdES/PAdES
		return Collections.emptyList();
	}

	@Override
	public List<CertificateToken> getTimeStampValidationDataCertValues() {
		// Not applicable for CAdES/PAdES
		return Collections.emptyList();
	}

	@Override
	public List<CertificateRef> getSigningCertificateValues() {
		if (signingCertificateValues == null) {
			signingCertificateValues = new ArrayList<CertificateRef>();
			if (signedAttributes != null && signedAttributes.size() > 0) {
				final Attribute signingCertificateAttributeV1 = signedAttributes.get(id_aa_signingCertificate);
				if (signingCertificateAttributeV1 != null) {
					signingCertificateValues.addAll(extractSigningCertificateV1(signingCertificateAttributeV1));
				}
				final Attribute signingCertificateAttributeV2 = signedAttributes.get(id_aa_signingCertificateV2);
				if (signingCertificateAttributeV2 != null) {
					signingCertificateValues.addAll(extractSigningCertificateV2(signingCertificateAttributeV2));
				}
			}
		}
		return signingCertificateValues;
	}

	private List<CertificateRef> extractSigningCertificateV1(Attribute attribute) {
		List<CertificateRef> certificateRefs = new ArrayList<CertificateRef>();
		final ASN1Set attrValues = attribute.getAttrValues();
		for (int ii = 0; ii < attrValues.size(); ii++) {
			final ASN1Encodable asn1Encodable = attrValues.getObjectAt(ii);
			final SigningCertificate signingCertificate = SigningCertificate.getInstance(asn1Encodable);
			if (signingCertificate != null) {
				certificateRefs.addAll(extractESSCertIDs(signingCertificate.getCerts(), CertificateRefOrigin.SIGNING_CERTIFICATE));
			} else {
				LOG.warn("SigningCertificate attribute is not well defined!");
			}
		}
		return certificateRefs;
	}

	private List<CertificateRef> extractESSCertIDs(final ESSCertID[] essCertIDs, CertificateRefOrigin location) {
		List<CertificateRef> certificateRefs = new ArrayList<CertificateRef>();
		for (final ESSCertID essCertID : essCertIDs) {
			CertificateRef certRef = new CertificateRef();

			final byte[] certHash = essCertID.getCertHash();
			if (Utils.isArrayNotEmpty(certHash)) {
				certRef.setCertDigest(new Digest(DigestAlgorithm.SHA1, certHash));
				if (LOG.isDebugEnabled()) {
					LOG.debug("Found Certificate Hash in signingCertificateAttributeV1 {} with algorithm {}", Utils.toHex(certHash), DigestAlgorithm.SHA1);
				}
			}

			final IssuerSerial issuerSerial = essCertID.getIssuerSerial();
			if (issuerSerial != null) {
				certRef.setIssuerInfo(DSSASN1Utils.getIssuerInfo(issuerSerial));
			}
			certRef.setOrigin(location);

			certificateRefs.add(certRef);
		}
		return certificateRefs;
	}

	private List<CertificateRef> extractSigningCertificateV2(Attribute attribute) {
		List<CertificateRef> certificateRefs = new ArrayList<CertificateRef>();
		final ASN1Set attrValues = attribute.getAttrValues();
		for (int ii = 0; ii < attrValues.size(); ii++) {
			final ASN1Encodable asn1Encodable = attrValues.getObjectAt(ii);
			final SigningCertificateV2 signingCertificate = SigningCertificateV2.getInstance(asn1Encodable);
			if (signingCertificate != null) {
				certificateRefs.addAll(extractESSCertIDv2s(signingCertificate.getCerts(), CertificateRefOrigin.SIGNING_CERTIFICATE));
			}
		}
		return certificateRefs;
	}

	private List<CertificateRef> extractESSCertIDv2s(ESSCertIDv2[] essCertIDv2s, CertificateRefOrigin location) {
		List<CertificateRef> certificateRefs = new ArrayList<CertificateRef>();
		for (final ESSCertIDv2 essCertIDv2 : essCertIDv2s) {
			CertificateRef certRef = new CertificateRef();
			final String algorithmId = essCertIDv2.getHashAlgorithm().getAlgorithm().getId();
			final DigestAlgorithm digestAlgorithm = DigestAlgorithm.forOID(algorithmId);
			final byte[] certHash = essCertIDv2.getCertHash();
			certRef.setCertDigest(new Digest(digestAlgorithm, certHash));
			if (LOG.isDebugEnabled()) {
				LOG.debug("Found Certificate Hash in SigningCertificateV2 {} with algorithm {}", Utils.toHex(certHash), digestAlgorithm);
			}
			final IssuerSerial issuerSerial = essCertIDv2.getIssuerSerial();
			if (issuerSerial != null) {
				certRef.setIssuerInfo(DSSASN1Utils.getIssuerInfo(issuerSerial));
			}
			certRef.setOrigin(location);
			certificateRefs.add(certRef);
		}
		return certificateRefs;
	}

}
