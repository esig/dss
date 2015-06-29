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
package eu.europa.esig.dss.cades.signature;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.SignatureLevel;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DefaultAdvancedSignature;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.OCSPToken;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.tsp.TSPSource;

/**
 * This class holds the CAdES-LT signature profiles
 *
 *
 */

public class CAdESLevelBaselineLT extends CAdESSignatureExtension {

	private final CertificateVerifier certificateVerifier;
	private final CAdESLevelBaselineT cadesProfileT;

	public CAdESLevelBaselineLT(TSPSource signatureTsa, CertificateVerifier certificateVerifier, boolean onlyLastSigner) {
		super(signatureTsa, onlyLastSigner);
		this.certificateVerifier = certificateVerifier;
		cadesProfileT = new CAdESLevelBaselineT(signatureTsa, onlyLastSigner);
	}

	@Override
	protected SignerInformation extendCMSSignature(CMSSignedData cmsSignedData, SignerInformation signerInformation, CAdESSignatureParameters parameters) throws DSSException {

		// add a LT level or replace an existing LT level
		CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
		cadesSignature.setDetachedContents(parameters.getDetachedContent());
		assertExtendSignaturePossible(cadesSignature, parameters);
		if (!cadesSignature.isDataForSignatureLevelPresent(SignatureLevel.CAdES_BASELINE_T)) {
			signerInformation = cadesProfileT.extendCMSSignature(cmsSignedData, signerInformation, parameters);
		}

		return signerInformation;
	}

	@Override
	protected CMSSignedData postExtendCMSSignedData(CMSSignedData cmsSignedData, SignerInformation signerInformation, CAdESSignatureParameters parameters) {
		CAdESSignature cadesSignature = new CAdESSignature(cmsSignedData, signerInformation);
		cadesSignature.setDetachedContents(parameters.getDetachedContent());
		final ValidationContext validationContext = cadesSignature.getSignatureValidationContext(certificateVerifier);

		Store certificatesStore = cmsSignedData.getCertificates();
		final Set<CertificateToken> certificates = cadesSignature.getCertificatesForInclusion(validationContext);
		final Collection<X509CertificateHolder> newCertificateStore = new HashSet<X509CertificateHolder>(certificatesStore.getMatches(null));
		for (final CertificateToken certificateToken : certificates) {
			final X509CertificateHolder x509CertificateHolder = certificateToken.getX509CertificateHolder();
			newCertificateStore.add(x509CertificateHolder);
		}
		certificatesStore = new CollectionStore(newCertificateStore);

		Store crlsStore = cmsSignedData.getCRLs();
		final Collection<X509CRLHolder> newCrlsStore = new HashSet<X509CRLHolder>(crlsStore.getMatches(null));
		final DefaultAdvancedSignature.RevocationDataForInclusion revocationDataForInclusion = cadesSignature.getRevocationDataForInclusion(validationContext);
		for (final CRLToken crlToken : revocationDataForInclusion.crlTokens) {
			final X509CRLHolder x509CRLHolder = crlToken.getX509CrlHolder();
			newCrlsStore.add(x509CRLHolder);
		}
		crlsStore = new CollectionStore(newCrlsStore);

		Store otherRevocationInfoFormatStoreBasic = cmsSignedData.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
		final Collection<ASN1Primitive> newOtherRevocationInfoFormatStore = new HashSet<ASN1Primitive>(otherRevocationInfoFormatStoreBasic.getMatches(null));
		for (final OCSPToken ocspToken : revocationDataForInclusion.ocspTokens) {
			final BasicOCSPResp basicOCSPResp = ocspToken.getBasicOCSPResp();
			newOtherRevocationInfoFormatStore.add(DSSASN1Utils.toASN1Primitive(DSSUtils.getEncoded(basicOCSPResp)));
		}
		otherRevocationInfoFormatStoreBasic = new CollectionStore(newOtherRevocationInfoFormatStore);

		Store attributeCertificatesStore = cmsSignedData.getAttributeCertificates();
		Store otherRevocationInfoFormatStoreOcsp = cmsSignedData.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response);

		final CMSSignedDataBuilder cmsSignedDataBuilder = new CMSSignedDataBuilder(certificateVerifier);
		cmsSignedData = cmsSignedDataBuilder
				.regenerateCMSSignedData(cmsSignedData, parameters, certificatesStore, attributeCertificatesStore, crlsStore, otherRevocationInfoFormatStoreBasic,
						otherRevocationInfoFormatStoreOcsp);
		return cmsSignedData;
	}

	/**
	 * @param cadesSignature
	 * @param parameters
	 */
	private void assertExtendSignaturePossible(CAdESSignature cadesSignature, CAdESSignatureParameters parameters) throws DSSException {
		//        if (cadesSignature.isDataForSignatureLevelPresent(SignatureLevel.CAdES_BASELINE_LTA)) {
		//            final String exceptionMessage = "Cannot extend signature. The signedData is already extended with [%s].";
		//            throw new DSSException(String.format(exceptionMessage, "CAdES LTA"));
		//        }
	}
}
