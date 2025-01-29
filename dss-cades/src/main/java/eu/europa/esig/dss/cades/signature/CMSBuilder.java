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
package eu.europa.esig.dss.cades.signature;

import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.cms.CMSGenerator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.x509.BaselineBCertificateSelector;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Builds a {@code CMS}
 *
 */
public class CMSBuilder {

	/**
	 * The signing-certificate to generate CMSSignedData with
	 */
	private CertificateToken signingCertificate;

	/**
	 * The certificate hain to be incorporated within SignedData.certificates field
	 */
	private Collection<CertificateToken> certificateChain;

	/**
	 * Defines whether a CMSSignedData should be generated without certificates inside.
	 */
	private boolean generateWithoutCertificates = false;

	/**
	 * Contains a list of trusted certificate sources (see {@code trustAnchorBPPolicy})
	 */
	private CertificateSource trustedCertificateSource;

	/**
	 * Indicates whether a trust anchor policy should be used.
	 * When enabled, the trust anchor is not included to the generated certificate chain.
	 * Otherwise, the chain is generated up to a trust anchor, including the trust anchor itself.
	 */
	private boolean trustAnchorBPPolicy = true;

	/**
	 * The original CMS to be used on creation of a new CMS in a way
	 * that all original field values will be copied to a new CMS
	 */
	private CMS originalCMS;

	/**
	 * Sets whether a signer content shall be encapsulated to a CMSSignedData
	 */
	private boolean encapsulate = true;

	/**
	 * This is the default constructor for {@code CMSSignedDataBuilder}.
	 */
	public CMSBuilder() {
		// empty
	}

	/**
	 * Sets a signing-certificate to be used for CMSSignedData generation
	 *
	 * @param signingCertificate {@link CertificateToken}
	 * @return this {@link CMSBuilder}
	 */
	public CMSBuilder setSigningCertificate(CertificateToken signingCertificate) {
		this.signingCertificate = signingCertificate;
		return this;
	}

	/**
	 * Sets a collection of certificates to be incorporated within SignedData.certificates field
	 *
	 * @param certificateChain a collection of {@link CertificateToken}s
	 * @return this {@link CMSBuilder}
	 */
	public CMSBuilder setCertificateChain(Collection<CertificateToken> certificateChain) {
		this.certificateChain = certificateChain;
		return this;
	}

	/**
	 * Sets whether CMSSignedData is to be generated without certificates inside.
	 * Default : FALSE (an attempt to generate without certificates will result to an exception)
	 *
	 * @param generateWithoutCertificates whether CMSSignedData is to be generated without certificates
	 * @return this {@link CMSBuilder}
	 */
	public CMSBuilder setGenerateWithoutCertificates(boolean generateWithoutCertificates) {
		this.generateWithoutCertificates = generateWithoutCertificates;
		return this;
	}

	/**
	 * Sets a trusted certificate source. See {@code trustAnchorBPPolicy} for more details.
	 *
	 * @param trustedCertificateSource {@link CertificateSource}
	 * @return this {@link CMSBuilder}
	 */
	public CMSBuilder setTrustedCertificateSource(CertificateSource trustedCertificateSource) {
		this.trustedCertificateSource = trustedCertificateSource;
		return this;
	}

	/**
	 * Sets whether a B-level trust anchor policy should be used.
	 * When enabled, the trust anchor is not included to the generated certificate chain.
	 * Otherwise, the chain is generated up to a trust anchor, including the trust anchor itself.
	 * Default : TRUE (the certificate chain will be generated up to a trust anchor, excluded)
	 *
	 * @param trustAnchorBPPolicy whether a B-level trust anchor policy should be used
	 * @return this {@link CMSBuilder}
	 */
	public CMSBuilder setTrustAnchorBPPolicy(boolean trustAnchorBPPolicy) {
		this.trustAnchorBPPolicy = trustAnchorBPPolicy;
		return this;
	}

	/**
	 * Sets the original CMSSignedData, which internal field values will be copied to a new CMSSignedData
	 *
	 * @param originalCMS {@link CMS}
	 * @return this {@link CMSBuilder}
	 */
	public CMSBuilder setOriginalCMS(CMS originalCMS) {
		this.originalCMS = originalCMS;
		return this;
	}

	/**
	 * Sets whether a signer content shall be encapsulated to the CMSSignedData.
	 * When enabled creates an enveloping signature, otherwise creates detached signature.
	 * Default : TRUE (the signer content is included to the signature)
	 *
	 * @param encapsulate whether signer content shall be encapsulated to the CMSSignedData
	 * @return this {@link CMSBuilder}
	 */
	public CMSBuilder setEncapsulate(boolean encapsulate) {
		this.encapsulate = encapsulate;
		return this;
	}

	/**
	 * Builds a {@code CMSSignedData}
	 *
	 * @param signerInfoGenerator {@link SignerInfoGenerator}
	 * @param toSignDocument {@link DSSDocument}
	 * @return {@link CMSSignedData}
	 */
	public CMS createCMS(SignerInfoGenerator signerInfoGenerator, DSSDocument toSignDocument) {
		final CMSGenerator generator = CMSGenerator.loadCMSGenerator();

		generator.setSignerInfoGenerator(signerInfoGenerator);
		generator.setCertificates(getCertificateStore());
		generator.setDigestAlgorithmIDs(getDigestAlgorithmIDs(signerInfoGenerator));

		generator.setToBeSignedDocument(toSignDocument);
		generator.setEncapsulate(encapsulate);

		if (originalCMS != null) {
			generator.setSigners(originalCMS.getSignerInfos());
			generator.setAttributeCertificates(originalCMS.getAttributeCertificates());
			generator.setCRLs(originalCMS.getCRLs());
			generator.setOcspBasicStore(originalCMS.getOcspBasicStore());
			generator.setOcspResponsesStore(originalCMS.getOcspResponseStore());
		}

		return generator.generate();
	}

	/**
	 * Returns a certificate store
	 *
	 * @return {@link Store}
	 */
	@SuppressWarnings("unchecked")
	private Store<X509CertificateHolder> getCertificateStore() {
		final List<CertificateToken> certificates = new LinkedList<>();
		if (originalCMS != null) {
			final Store<X509CertificateHolder> certificateStore = originalCMS.getCertificates();
			final Collection<X509CertificateHolder> certificatesMatches = certificateStore.getMatches(null);
			for (final X509CertificateHolder certificatesMatch : certificatesMatches) {
				final CertificateToken token = DSSASN1Utils.getCertificate(certificatesMatch);
				if (!certificates.contains(token)) {
					certificates.add(token);
				}
			}
		}
		return getJcaCertStore(certificates);
	}

	/**
	 * The order of the certificates is important, the fist one must be the signing certificate.
	 *
	 * @param certificates a collection of {@link CertificateToken}s to be added
	 * @return a store with the certificate chain of the signing certificate. The {@code Collection} is unique.
	 */
	private JcaCertStore getJcaCertStore(final Collection<CertificateToken> certificates) {
		List<CertificateToken> certificatesToAdd;
		if (signingCertificate == null && generateWithoutCertificates) {
			certificatesToAdd = new ArrayList<>();
		} else {
			certificatesToAdd = new BaselineBCertificateSelector(signingCertificate, certificateChain)
					.setTrustedCertificateSource(trustedCertificateSource)
					.setTrustAnchorBPPolicy(trustAnchorBPPolicy)
					.getCertificates();
		}

		for (CertificateToken certificateToken : certificatesToAdd) {
			if (!certificates.contains(certificateToken)) {
				certificates.add(certificateToken);
			}
		}

		try {
			final Collection<X509Certificate> certs = new ArrayList<>();
			for (final CertificateToken certificateToken : certificates) {
				certs.add(certificateToken.getCertificate());
			}
			return new JcaCertStore(certs);
		} catch (CertificateEncodingException e) {
			throw new DSSException(String.format("Unable to get JcaCertStore. Reason : %s", e.getMessage()), e);
		}
	}

	private Set<AlgorithmIdentifier> getDigestAlgorithmIDs(SignerInfoGenerator signerInfoGenerator) {
		Set<AlgorithmIdentifier> digestAlgorithmIDs = new HashSet<>();
		if (originalCMS != null) {
			digestAlgorithmIDs.addAll(originalCMS.getDigestAlgorithmIDs());
		}
		digestAlgorithmIDs.add(signerInfoGenerator.getDigestAlgorithm());
		return digestAlgorithmIDs;
	}
	
	/**
	 * Extends the provided {@code originalCMS} with the required validation data
	 *
	 * @param certificateTokens a collection of {@link CertificateToken}s
	 * @param crlTokens a collection of {@link CRLToken}s
	 * @param ocspTokens a collection of {@link OCSPToken}s
	 * @return extended {@link CMS}
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public CMS extendCMSSignedData(Collection<CertificateToken> certificateTokens, Collection<CRLToken> crlTokens,
								   Collection<OCSPToken> ocspTokens) {
		if (originalCMS == null) {
			throw new NullPointerException("Original CMSSignedData shall be provided! " +
					"Use #setOriginalCMSSignedData(CMSSignedData) method.");
		}

		Store<X509CertificateHolder> certificatesStore = originalCMS.getCertificates();
		final Collection<X509CertificateHolder> newCertificateStore = new HashSet<>(certificatesStore.getMatches(null));
		for (final CertificateToken certificateToken : certificateTokens) {
			final X509CertificateHolder x509CertificateHolder = DSSASN1Utils.getX509CertificateHolder(certificateToken);
			if (!newCertificateStore.contains(x509CertificateHolder)) {
				newCertificateStore.add(x509CertificateHolder);
			}
		}
		certificatesStore = new CollectionStore<>(newCertificateStore);

		Store attributeCertificatesStore = originalCMS.getAttributeCertificates();

		Store<X509CRLHolder> crlsStore = originalCMS.getCRLs();
		final Collection<Encodable> newCrlsStore = new HashSet<>(crlsStore.getMatches(null));
		for (final CRLToken crlToken : crlTokens) {
			final X509CRLHolder x509CRLHolder = getX509CrlHolder(crlToken);
			if (!newCrlsStore.contains(x509CRLHolder)) {
				newCrlsStore.add(x509CRLHolder);
			}
		}
		crlsStore = new CollectionStore(newCrlsStore);

		Store otherRevocationInfoFormatStoreOcsp = originalCMS.getOcspResponseStore();
		final Collection<ASN1Primitive> newOtherRevocationInfoFormatStore = new HashSet<>(otherRevocationInfoFormatStoreOcsp.getMatches(null));
		for (final OCSPToken ocspToken : ocspTokens) {
			ASN1Primitive ocspResponseASN1Primitive = DSSASN1Utils.toASN1Primitive(ocspToken.getEncoded());
			if (!newOtherRevocationInfoFormatStore.contains(ocspResponseASN1Primitive)) {
				newOtherRevocationInfoFormatStore.add(ocspResponseASN1Primitive);
			}
		}
		otherRevocationInfoFormatStoreOcsp = new CollectionStore(newOtherRevocationInfoFormatStore);

		Store otherRevocationInfoFormatStoreBasic = originalCMS.getOcspBasicStore();


		final CMSGenerator cmsGenerator = CMSGenerator.loadCMSGenerator();
		cmsGenerator.setCertificates(certificatesStore);
		cmsGenerator.setAttributeCertificates(attributeCertificatesStore);
		cmsGenerator.setCRLs(crlsStore);
		cmsGenerator.setOcspResponsesStore(otherRevocationInfoFormatStoreOcsp);
		cmsGenerator.setOcspBasicStore(otherRevocationInfoFormatStoreBasic);

		return cmsGenerator.replaceCertificatesAndCRLs(originalCMS);
	}

	/**
	 * Gets a {@code X509CRLHolder} generated from a {@code CRLToken}
	 *
	 * @return a copy of x509crl as a X509CRLHolder
	 */
	private X509CRLHolder getX509CrlHolder(CRLToken crlToken) {
		try (InputStream is = crlToken.getCRLStream()) {
			return new X509CRLHolder(is);
		} catch (IOException e) {
			throw new DSSException("Unable to convert X509CRL to X509CRLHolder", e);
		}
	}

}
