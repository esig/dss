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
package eu.europa.esig.dss.spi.x509;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
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
import java.util.Objects;

import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.id_ri_ocsp_response;
import static org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_basic;

/**
 * Builds a CMSSignedData
 *
 */
public class CMSSignedDataBuilder {

	/**
	 * The signing-certificate to generate CMSSignedData with
	 */
	private CertificateToken signingCertificate;

	/**
	 * The certificate hain to be incorporated within CMSSignedData.certificates field
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
	 * The original CMSSignedData to be used on a new CMSSignedData in a way
	 * that all original field values will be copied to a new CMSSignedData
	 */
	private CMSSignedData originalCMSSignedData;

	/**
	 * Sets whether a signer content shall be encapsulated to a CMSSignedData
	 */
	private boolean encapsulate = true;

	/**
	 * This is the default constructor for {@code CMSSignedDataBuilder}.
	 */
	public CMSSignedDataBuilder() {
		// empty
	}

	/**
	 * Sets a signing-certificate to be used for CMSSignedData generation
	 *
	 * @param signingCertificate {@link CertificateToken}
	 * @return this {@link CMSSignedDataBuilder}
	 */
	public CMSSignedDataBuilder setSigningCertificate(CertificateToken signingCertificate) {
		this.signingCertificate = signingCertificate;
		return this;
	}

	/**
	 * Sets a collection of certificates to be incorporated within CMSSignedData.certificates field
	 *
	 * @param certificateChain a collection of {@link CertificateToken}s
	 * @return this {@link CMSSignedDataBuilder}
	 */
	public CMSSignedDataBuilder setCertificateChain(Collection<CertificateToken> certificateChain) {
		this.certificateChain = certificateChain;
		return this;
	}

	/**
	 * Sets whether CMSSignedData is to be generated without certificates inside.
	 * Default : FALSE (an attempt to generate without certificates will result to an exception)
	 *
	 * @param generateWithoutCertificates whether CMSSignedData is to be generated without certificates
	 * @return this {@link CMSSignedDataBuilder}
	 */
	public CMSSignedDataBuilder setGenerateWithoutCertificates(boolean generateWithoutCertificates) {
		this.generateWithoutCertificates = generateWithoutCertificates;
		return this;
	}

	/**
	 * Sets a trusted certificate source. See {@code trustAnchorBPPolicy} for more details.
	 *
	 * @param trustedCertificateSource {@link CertificateSource}
	 * @return this {@link CMSSignedDataBuilder}
	 */
	public CMSSignedDataBuilder setTrustedCertificateSource(CertificateSource trustedCertificateSource) {
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
	 * @return this {@link CMSSignedDataBuilder}
	 */
	public CMSSignedDataBuilder setTrustAnchorBPPolicy(boolean trustAnchorBPPolicy) {
		this.trustAnchorBPPolicy = trustAnchorBPPolicy;
		return this;
	}

	/**
	 * Sets the original CMSSignedData, which internal field values will be copied to a new CMSSignedData
	 *
	 * @param originalCMSSignedData {@link CMSSignedData}
	 * @return this {@link CMSSignedDataBuilder}
	 */
	public CMSSignedDataBuilder setOriginalCMSSignedData(CMSSignedData originalCMSSignedData) {
		this.originalCMSSignedData = originalCMSSignedData;
		return this;
	}

	/**
	 * Sets whether a signer content shall be encapsulated to the CMSSignedData.
	 * When enabled creates an enveloping signature, otherwise creates detached signature.
	 * Default : TRUE (the signer content is included to the signature)
	 *
	 * @param encapsulate whether signer content shall be encapsulated to the CMSSignedData
	 * @return this {@link CMSSignedDataBuilder}
	 */
	public CMSSignedDataBuilder setEncapsulate(boolean encapsulate) {
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
	public CMSSignedData createCMSSignedData(SignerInfoGenerator signerInfoGenerator, DSSDocument toSignDocument) {
		final CMSSignedDataGenerator cmsSignedDataGenerator = createCMSSignedDataGenerator(signerInfoGenerator);
		final CMSTypedData contentToBeSigned = getContentToBeSigned(toSignDocument);
		return generateCMSSignedData(cmsSignedDataGenerator, contentToBeSigned);
	}

	/**
	 * Note:
	 * Section 5.1 of RFC 3852 [4] requires that, the CMS SignedData version be set to 3 if certificates from
	 * SignedData is present AND (any version 1 attribute certificates are present OR any SignerInfo structures
	 * are version 3 OR eContentType from encapContentInfo is other than id-data). Otherwise, the CMS
	 * SignedData version is required to be set to 1.
	 * CMS SignedData Version is handled automatically by BouncyCastle.
	 *
	 * @param signerInfoGenerator
	 *            the signer info generator
	 * @return the bouncycastle signed data generator which signs the document and adds the required signed and unsigned
	 *         CMS attributes
	 */
	public CMSSignedDataGenerator createCMSSignedDataGenerator(SignerInfoGenerator signerInfoGenerator) {
		try {
			final CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

			generator.addSignerInfoGenerator(signerInfoGenerator);

			final List<CertificateToken> certificates = new LinkedList<>();
			if (originalCMSSignedData != null) {

				generator.addSigners(originalCMSSignedData.getSignerInfos());
				generator.addAttributeCertificates(originalCMSSignedData.getAttributeCertificates());
				generator.addCRLs(originalCMSSignedData.getCRLs());
				generator.addOtherRevocationInfo(id_pkix_ocsp_basic, originalCMSSignedData.getOtherRevocationInfo(id_pkix_ocsp_basic));
				generator.addOtherRevocationInfo(id_ri_ocsp_response, originalCMSSignedData.getOtherRevocationInfo(id_ri_ocsp_response));

				final Store<X509CertificateHolder> certificateStore = originalCMSSignedData.getCertificates();
				final Collection<X509CertificateHolder> certificatesMatches = certificateStore.getMatches(null);
				for (final X509CertificateHolder certificatesMatch : certificatesMatches) {
					final CertificateToken token = DSSASN1Utils.getCertificate(certificatesMatch);
					if (!certificates.contains(token)) {
						certificates.add(token);
					}
				}

			}

			final JcaCertStore jcaCertStore = getJcaCertStore(certificates);
			generator.addCertificates(jcaCertStore);
			return generator;

		} catch (CMSException e) {
			throw new DSSException(String.format("Unable to create a CMSSignedDataGenerator. Reason : %s", e.getMessage()), e);
		}
	}

	/**
	 * Returns the content to be signed
	 *
	 * @param toSignData {@link DSSDocument} to sign
	 * @return {@link CMSTypedData}
	 */
	protected CMSTypedData getContentToBeSigned(final DSSDocument toSignData) {
		Objects.requireNonNull(toSignData, "Document to be signed is missing");
		CMSTypedData content;
		if (toSignData instanceof DigestDocument) {
			content = new CMSAbsentContent();
		} else if (toSignData instanceof FileDocument) {
			FileDocument fileDocument = (FileDocument) toSignData;
			content = new CMSProcessableFile(fileDocument.getFile());
		} else {
			content = new CMSProcessableByteArray(DSSUtils.toByteArray(toSignData));
		}
		return content;
	}

	/**
	 * This method generate {@code CMSSignedData} using the provided #{@code CMSSignedDataGenerator}, the content and
	 * the indication if the content should be encapsulated.
	 *
	 * @param generator {@link CMSSignedDataGenerator}
	 * @param content {@link CMSTypedData}
	 * @return {@link CMSSignedData}
	 */
	private CMSSignedData generateCMSSignedData(final CMSSignedDataGenerator generator, final CMSTypedData content) {
		try {
			CMSSignedData cmsSignedData = generator.generate(content, encapsulate);
			return populateDigestAlgorithmSet(cmsSignedData);
		} catch (CMSException e) {
			throw new DSSException("Unable to generate the CMSSignedData", e);
		}
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
	
	/**
	 * Extends the provided {@code cmsSignedData} with the required validation data
	 *
	 * @param certificateTokens a collection of {@link CertificateToken}s
	 * @param crlTokens a collection of {@link CRLToken}s
	 * @param ocspTokens a collection of {@link OCSPToken}s
	 * @return extended {@link CMSSignedData}
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public CMSSignedData extendCMSSignedData(Collection<CertificateToken> certificateTokens, Collection<CRLToken> crlTokens,
											 Collection<OCSPToken> ocspTokens) {
		if (originalCMSSignedData == null) {
			throw new NullPointerException("Original CMSSignedData shall be provided! " +
					"Use #setOriginalCMSSignedData(CMSSignedData) method.");
		}

		Store<X509CertificateHolder> certificatesStore = originalCMSSignedData.getCertificates();
		final Collection<X509CertificateHolder> newCertificateStore = new HashSet<>(certificatesStore.getMatches(null));
		for (final CertificateToken certificateToken : certificateTokens) {
			final X509CertificateHolder x509CertificateHolder = DSSASN1Utils.getX509CertificateHolder(certificateToken);
			if (!newCertificateStore.contains(x509CertificateHolder)) {
				newCertificateStore.add(x509CertificateHolder);
			}
		}
		certificatesStore = new CollectionStore<>(newCertificateStore);

		Store attributeCertificatesStore = originalCMSSignedData.getAttributeCertificates();

		Store<X509CRLHolder> crlsStore = originalCMSSignedData.getCRLs();
		final Collection<Encodable> newCrlsStore = new HashSet<>(crlsStore.getMatches(null));
		for (final CRLToken crlToken : crlTokens) {
			final X509CRLHolder x509CRLHolder = getX509CrlHolder(crlToken);
			if (!newCrlsStore.contains(x509CRLHolder)) {
				newCrlsStore.add(x509CRLHolder);
			}
		}

		Store otherRevocationInfoFormatStoreOcsp = originalCMSSignedData.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response);
		final Collection<ASN1Primitive> newOtherRevocationInfoFormatStore = new HashSet<>(otherRevocationInfoFormatStoreOcsp.getMatches(null));
		for (final OCSPToken ocspToken : ocspTokens) {
			ASN1Primitive ocspResponseASN1Primitive = DSSASN1Utils.toASN1Primitive(ocspToken.getEncoded());
			if (!newOtherRevocationInfoFormatStore.contains(ocspResponseASN1Primitive)) {
				newOtherRevocationInfoFormatStore.add(ocspResponseASN1Primitive);
			}
		}

		otherRevocationInfoFormatStoreOcsp = new CollectionStore(newOtherRevocationInfoFormatStore);
		for (Object ocsp : otherRevocationInfoFormatStoreOcsp.getMatches(null)) {
			newCrlsStore.add(new OtherRevocationInfoFormat(CMSObjectIdentifiers.id_ri_ocsp_response, (ASN1Encodable) ocsp));
		}

		Store otherRevocationInfoFormatStoreBasic = originalCMSSignedData.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
		for (Object ocsp : otherRevocationInfoFormatStoreBasic.getMatches(null)) {
			newCrlsStore.add(new OtherRevocationInfoFormat(OCSPObjectIdentifiers.id_pkix_ocsp_basic, (ASN1Encodable) ocsp));
		}

		crlsStore = new CollectionStore(newCrlsStore);

		try {
			return CMSSignedData.replaceCertificatesAndCRLs(originalCMSSignedData,
					certificatesStore, attributeCertificatesStore, crlsStore);
		} catch (CMSException e) {
			throw new DSSException(String.format("Unable to re-create a CMS signature. Reason : %s", e.getMessage()), e);
		}
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

	/**
	 * This method is used to ensure the presence of all items from SignedData.digestAlgorithm set
	 * from {@code originalCMSSignedData} within {@code newCmsSignedData}
	 *
	 * @param newCmsSignedData {@link CMSSignedData} to be extended with digest algorithms, if required
	 * @return extended {@link CMSSignedData}
	 */
	protected CMSSignedData populateDigestAlgorithmSet(CMSSignedData newCmsSignedData) {
		if (originalCMSSignedData != null) {
			for (AlgorithmIdentifier algorithmIdentifier : originalCMSSignedData.getDigestAlgorithmIDs()) {
				newCmsSignedData = addDigestAlgorithm(newCmsSignedData, algorithmIdentifier);
			}
		}
		return newCmsSignedData;
	}

	/**
	 * This method adds a DigestAlgorithm used by an Archive TimeStamp to
	 * the SignedData.digestAlgorithms set, when required.
	 *
	 * See ETSI EN 319 122-1, ch. "5.5.3 The archive-time-stamp-v3 attribute"
	 *
	 * @param cmsSignedData {@link CMSSignedData} to extend
	 * @param algorithmIdentifier {@link AlgorithmIdentifier} to add
	 * @return {@link CMSSignedData}
	 */
	protected CMSSignedData addDigestAlgorithm(CMSSignedData cmsSignedData, AlgorithmIdentifier algorithmIdentifier) {
		return CMSSignedData.addDigestAlgorithm(cmsSignedData, algorithmIdentifier);
	}

}
