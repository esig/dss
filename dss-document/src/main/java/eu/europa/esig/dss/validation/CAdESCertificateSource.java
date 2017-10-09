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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.SignatureCertificateSource;

/**
 * CertificateSource that retrieves items from a CAdES Signature
 */
public class CAdESCertificateSource extends SignatureCertificateSource {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESCertificateSource.class);

	private List<CertificateToken> keyInfoCerts;
	private List<CertificateToken> encapsulatedCerts;

	/**
	 * The constructor with additional signer id parameter. All certificates are extracted during instantiation.
	 *
	 * @param cmsSignedData
	 * @param certPool
	 */
	public CAdESCertificateSource(final CMSSignedData cmsSignedData, final CertificatePool certPool) {
		super(certPool);
		if (cmsSignedData == null) {
			throw new DSSException("CMS SignedData is null, it must be provided!");
		}
		if (certificateTokens == null) {
			certificateTokens = new ArrayList<CertificateToken>();
			keyInfoCerts = extractIdSignedDataCertificates(cmsSignedData);
			encapsulatedCerts = extractEncapsulatedCertificates(cmsSignedData);
		}
	}

	/**
	 * Returns the list of certificates included in (XAdES equivalent)
	 * ".../xades:UnsignedSignatureProperties/xades:CertificateValues/xades:EncapsulatedX509Certificate" node
	 *
	 * @return list of X509Certificate(s)
	 */
	@Override
	public List<CertificateToken> getEncapsulatedCertificates() {
		return encapsulatedCerts;
	}

	private List<CertificateToken> extractEncapsulatedCertificates(CMSSignedData cmsSignedData) {
		final List<CertificateToken> encapsulatedCerts = new ArrayList<CertificateToken>();
		// Gets certificates from CAdES-XL certificate-values inside SignerInfo attribute if present
		SignerInformation signerInformation = DSSASN1Utils.getFirstSignerInformation(cmsSignedData);
		if ((signerInformation != null) && (signerInformation.getUnsignedAttributes() != null)) {
			AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
			extractCertificateFromUnsignedAttribute(encapsulatedCerts, unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_ets_certValues));
			extractCertificateFromUnsignedAttribute(encapsulatedCerts, unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs));
		}
		return encapsulatedCerts;
	}

	private void extractCertificateFromUnsignedAttribute(List<CertificateToken> encapsulatedCerts, Attribute attribute) {
		if (attribute != null) {
			final ASN1Sequence seq = (ASN1Sequence) attribute.getAttrValues().getObjectAt(0);
			for (int ii = 0; ii < seq.size(); ii++) {
				try {
					final Certificate cs = Certificate.getInstance(seq.getObjectAt(ii));
					final CertificateToken certToken = addCertificate(DSSUtils.loadCertificate(cs.getEncoded()));
					if (!encapsulatedCerts.contains(certToken)) {
						encapsulatedCerts.add(certToken);
					}
				} catch (Exception e) {
					LOG.warn("Unable to parse encapsulated certificate : " + e.getMessage());
				}
			}
		}
	}

	/**
	 * Returns the list of certificates included in CAdES equivalent of XAdES
	 * "ds:KeyInfo/ds:X509Data/ds:X509Certificate" node.
	 * <p/>
	 * They are extracted from id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549)
	 * pkcs(1) pkcs7(7) 2 }
	 * <p/>
	 * SignedData ::= SEQUENCE {<br>
	 * - version CMSVersion,<br>
	 * - digestAlgorithms DigestAlgorithmIdentifiers,<br>
	 * - encapContentInfo EncapsulatedContentInfo,<br>
	 * - {@code certificates} [0] IMPLICIT CertificateSet OPTIONAL,<br>
	 * - crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,<br>
	 * - signerInfos SignerInfos<br>
	 * }<br>
	 *
	 * @return list of X509Certificate(s)
	 */
	@Override
	public List<CertificateToken> getKeyInfoCertificates() {
		return keyInfoCerts;
	}

	private List<CertificateToken> extractIdSignedDataCertificates(CMSSignedData cmsSignedData) {
		final List<CertificateToken> essCertIDCerts = new ArrayList<CertificateToken>();
		try {
			final Collection<X509CertificateHolder> x509CertificateHolders = cmsSignedData.getCertificates().getMatches(null);
			for (final X509CertificateHolder x509CertificateHolder : x509CertificateHolders) {
				final CertificateToken x509Certificate = DSSASN1Utils.getCertificate(x509CertificateHolder);
				final CertificateToken certificateToken = addCertificate(x509Certificate);
				if (!essCertIDCerts.contains(certificateToken)) {
					essCertIDCerts.add(certificateToken);
				}
			}
		} catch (Exception e) {
			LOG.warn("Cannot extract certificates from CMS Signed Data : " + e.getMessage());
		}
		return essCertIDCerts;
	}
}
