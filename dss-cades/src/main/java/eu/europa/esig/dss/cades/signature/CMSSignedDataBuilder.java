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

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.CMSUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.BaselineBCertificateSelector;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationDataForInclusion;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.CollectionStore;
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

import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.id_ri_ocsp_response;
import static org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_basic;

/**
 * Builds a CMSSignedData
 */
public class CMSSignedDataBuilder {

	/**
	 * The CertificateVerifier to use for a certificate chain validation
	 */
	private final CertificateVerifier certificateVerifier;

	/**
	 * This is the default constructor for {@code CMSSignedDataGeneratorBuilder}. The {@code CertificateVerifier} is
	 * used to find the trusted certificates.
	 *
	 * @param certificateVerifier
	 *            {@code CertificateVerifier} provides information on the sources to be used in the validation process
	 *            in the context of a signature.
	 */
	public CMSSignedDataBuilder(final CertificateVerifier certificateVerifier) {
		this.certificateVerifier = certificateVerifier;
	}

	/**
	 * Note:
	 * Section 5.1 of RFC 3852 [4] requires that, the CMS SignedData version be set to 3 if certificates from
	 * SignedData is present AND (any version 1 attribute certificates are present OR any SignerInfo structures
	 * are version 3 OR eContentType from encapContentInfo is other than id-data). Otherwise, the CMS
	 * SignedData version is required to be set to 1.
	 * CMS SignedData Version is handled automatically by BouncyCastle.
	 *
	 * @param parameters
	 *            set of the driving signing parameters
	 * @param contentSigner
	 *            the contentSigner to get the hash of the data to be signed
	 * @param signerInfoGeneratorBuilder
	 *            the builder for the signer info generator
	 * @param originalSignedData
	 *            the original signed data if extending an existing signature. null otherwise.
	 * @return the bouncycastle signed data generator which signs the document and adds the required signed and unsigned
	 *         CMS attributes
	 */
	protected CMSSignedDataGenerator createCMSSignedDataGenerator(final CAdESSignatureParameters parameters, final ContentSigner contentSigner,
			final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder, final CMSSignedData originalSignedData) {
		try {
			final CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
			final SignerInfoGenerator signerInfoGenerator = getSignerInfoGenerator(signerInfoGeneratorBuilder, contentSigner, parameters);

			generator.addSignerInfoGenerator(signerInfoGenerator);

			final List<CertificateToken> certificateChain = new LinkedList<>();
			if (originalSignedData != null) {

				generator.addSigners(originalSignedData.getSignerInfos());
				generator.addAttributeCertificates(originalSignedData.getAttributeCertificates());
				generator.addCRLs(originalSignedData.getCRLs());
				generator.addOtherRevocationInfo(id_pkix_ocsp_basic, originalSignedData.getOtherRevocationInfo(id_pkix_ocsp_basic));
				generator.addOtherRevocationInfo(id_ri_ocsp_response, originalSignedData.getOtherRevocationInfo(id_ri_ocsp_response));

				final Store<X509CertificateHolder> certificates = originalSignedData.getCertificates();
				final Collection<X509CertificateHolder> certificatesMatches = certificates.getMatches(null);
				for (final X509CertificateHolder certificatesMatch : certificatesMatches) {
					final CertificateToken token = DSSASN1Utils.getCertificate(certificatesMatch);
					if (!certificateChain.contains(token)) {
						certificateChain.add(token);
					}
				}
			}

			final JcaCertStore jcaCertStore = getJcaCertStore(certificateChain, parameters);
			generator.addCertificates(jcaCertStore);
			return generator;
		} catch (CMSException | OperatorCreationException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method creates a builder of SignerInfoGenerator
	 *
	 * @param digestCalculatorProvider
	 *            the digest calculator (can be pre-computed)
	 * @param parameters
	 *            the parameters of the signature containing values for the attributes
	 * @param includeUnsignedAttributes
	 *            true if the unsigned attributes must be included
	 * @return a SignerInfoGeneratorBuilder that generate the signed and unsigned attributes according to the
	 *         CAdESLevelBaselineB
	 */
	SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder(DigestCalculatorProvider digestCalculatorProvider, final CAdESSignatureParameters parameters,
			final boolean includeUnsignedAttributes) {

		final CAdESLevelBaselineB cadesProfile = new CAdESLevelBaselineB();
		final AttributeTable signedAttributes = cadesProfile.getSignedAttributes(parameters);

		AttributeTable unsignedAttributes = null;
		if (includeUnsignedAttributes) {
			unsignedAttributes = cadesProfile.getUnsignedAttributes();
		}
		return getSignerInfoGeneratorBuilder(digestCalculatorProvider, signedAttributes, unsignedAttributes);
	}

	/**
	 * This method creates a builder of SignerInfoGenerator
	 *
	 * @param digestCalculatorProvider
	 *            the digest calculator (can be pre-computed)
	 * @param signedAttributes
	 *            the signedAttributes
	 * @param unsignedAttributes
	 *            the unsignedAttributes
	 * @return a SignerInfoGeneratorBuilder that generate the signed and unsigned attributes according to the parameters
	 */
	private SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder(DigestCalculatorProvider digestCalculatorProvider, AttributeTable signedAttributes,
			AttributeTable unsignedAttributes) {

		if (DSSASN1Utils.isEmpty(signedAttributes)) {
			signedAttributes = null;
		}
		final DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributes);
		if (DSSASN1Utils.isEmpty(unsignedAttributes)) {
			unsignedAttributes = null;
		}
		final SimpleAttributeTableGenerator unsignedAttributeGenerator = new SimpleAttributeTableGenerator(unsignedAttributes);

		SignerInfoGeneratorBuilder sigInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider);
		sigInfoGeneratorBuilder.setSignedAttributeGenerator(signedAttributeGenerator);
		sigInfoGeneratorBuilder.setUnsignedAttributeGenerator(unsignedAttributeGenerator);
		return sigInfoGeneratorBuilder;
	}

	/**
	 * @param signerInfoGeneratorBuilder
	 *            the SignerInfoGeneratorBuilder
	 * @param contentSigner
	 *            the content signer
	 * @param parameters
	 *            set of the driving signing parameters
	 * @return SignerInfoGenerator generated by the given builder according to the parameters
	 * @throws OperatorCreationException
	 */
	private SignerInfoGenerator getSignerInfoGenerator(final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder, final ContentSigner contentSigner,
			CAdESSignatureParameters parameters) throws OperatorCreationException {
		final CertificateToken signingCertificate = parameters.getSigningCertificate();

		if (signingCertificate == null && parameters.isGenerateTBSWithoutCertificate()) {
			// Generate data-to-be-signed without signing certificate
			final SignerId signerId = new SignerId(DSSUtils.EMPTY_BYTE_ARRAY);
			return signerInfoGeneratorBuilder.build(contentSigner, signerId.getSubjectKeyIdentifier());
		}

		final X509CertificateHolder certHolder = DSSASN1Utils.getX509CertificateHolder(signingCertificate);
		return signerInfoGeneratorBuilder.build(contentSigner, certHolder);
	}

	/**
	 * The order of the certificates is important, the fist one must be the signing certificate.
	 *
	 * @return a store with the certificate chain of the signing certificate. The {@code Collection} is unique.
	 */
	private JcaCertStore getJcaCertStore(final Collection<CertificateToken> certificateChain, CAdESSignatureParameters parameters) {
		BaselineBCertificateSelector certificateSelectors = new BaselineBCertificateSelector(certificateVerifier, parameters);
		List<CertificateToken> certificatesToAdd;
		if (parameters.getSigningCertificate() == null && parameters.isGenerateTBSWithoutCertificate()) {
			certificatesToAdd = new ArrayList<>();
		} else {
			certificatesToAdd = certificateSelectors.getCertificates();
		}

		for (CertificateToken certificateToken : certificatesToAdd) {
			if (!certificateChain.contains(certificateToken)) {
				certificateChain.add(certificateToken);
			}
		}

		try {
			final Collection<X509Certificate> certs = new ArrayList<>();
			for (final CertificateToken certificateInChain : certificateChain) {
				certs.add(certificateInChain.getCertificate());
			}
			return new JcaCertStore(certs);
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Generates a new CMSSignedData with incorporation of defined validation data stores
	 *
	 * @param cmsSignedData {@link CMSSignedData} to be re-generated
	 * @param detachedContents a list of {@link DSSDocument}s to add (shall be one)
	 * @param certificatesStore {@link Store} of certificates
	 * @param attributeCertificatesStore {@link Store} of attribute certificates
	 * @param crlsStore {@link Store} of CRLs
	 * @param otherRevocationInfoFormatStoreBasic {@link Store} of other revocation data
	 * @param otherRevocationInfoFormatStoreOcsp {@link Store} of OCSPs
	 * @return {@link CMSSignedData}
	 */
	@SuppressWarnings("rawtypes")
	protected CMSSignedData regenerateCMSSignedData(CMSSignedData cmsSignedData, List<DSSDocument> detachedContents,
													Store certificatesStore, Store attributeCertificatesStore,
													Store crlsStore, Store otherRevocationInfoFormatStoreBasic,
													Store otherRevocationInfoFormatStoreOcsp) {
		try {

			final CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
			cmsSignedDataGenerator.addSigners(cmsSignedData.getSignerInfos());
			cmsSignedDataGenerator.addAttributeCertificates(attributeCertificatesStore);
			cmsSignedDataGenerator.addCertificates(certificatesStore);
			cmsSignedDataGenerator.addCRLs(crlsStore);
			cmsSignedDataGenerator.addOtherRevocationInfo(id_pkix_ocsp_basic, otherRevocationInfoFormatStoreBasic);
			cmsSignedDataGenerator.addOtherRevocationInfo(id_ri_ocsp_response, otherRevocationInfoFormatStoreOcsp);
			final boolean encapsulate = cmsSignedData.getSignedContent() != null;
			if (!encapsulate) {
				// CAdES can only sign one document
				final DSSDocument doc = detachedContents.get(0);
				final CMSTypedData content = CMSUtils.getContentToBeSigned(doc);
				cmsSignedData = cmsSignedDataGenerator.generate(content, encapsulate);
			} else {
				cmsSignedData = cmsSignedDataGenerator.generate(cmsSignedData.getSignedContent(), encapsulate);
			}
			return cmsSignedData;
		} catch (CMSException e) {
			throw new DSSException(e);
		}
	}
	
	/**
	 * Extends the provided {@code cmsSignedData} with the required validation data
	 * @param cmsSignedData {@link CMSSignedData} to be extended
	 * @param validationDataForInclusion the {@link ValidationDataForInclusion} to be included into the cmsSignedData
	 * @param detachedContents list of detached {@link DSSDocument}s
	 * @return extended {@link CMSSignedData}
	 */
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public CMSSignedData extendCMSSignedData(CMSSignedData cmsSignedData, ValidationDataForInclusion validationDataForInclusion, 
			List<DSSDocument> detachedContents) {

		Store<X509CertificateHolder> certificatesStore = cmsSignedData.getCertificates();
		final Set<CertificateToken> certificates = validationDataForInclusion.getCertificateTokens();
		final Collection<X509CertificateHolder> newCertificateStore = new HashSet<>(certificatesStore.getMatches(null));
		for (final CertificateToken certificateToken : certificates) {
			final X509CertificateHolder x509CertificateHolder = DSSASN1Utils.getX509CertificateHolder(certificateToken);
			newCertificateStore.add(x509CertificateHolder);
		}
		certificatesStore = new CollectionStore<>(newCertificateStore);

		Store<X509CRLHolder> crlsStore = cmsSignedData.getCRLs();
		final Collection<X509CRLHolder> newCrlsStore = new HashSet<>(crlsStore.getMatches(null));
		final List<CRLToken> crlTokens = validationDataForInclusion.getCrlTokens();
		for (final CRLToken crlToken : crlTokens) {
			final X509CRLHolder x509CRLHolder = getX509CrlHolder(crlToken);
			newCrlsStore.add(x509CRLHolder);
		}
		crlsStore = new CollectionStore<>(newCrlsStore);

		Store otherRevocationInfoFormatStoreBasic = cmsSignedData.getOtherRevocationInfo(OCSPObjectIdentifiers.id_pkix_ocsp_basic);
		final Collection<ASN1Primitive> newOtherRevocationInfoFormatStore = new HashSet<>(otherRevocationInfoFormatStoreBasic.getMatches(null));
		final List<OCSPToken> ocspTokens = validationDataForInclusion.getOcspTokens();
		for (final OCSPToken ocspToken : ocspTokens) {
			final BasicOCSPResp basicOCSPResp = ocspToken.getBasicOCSPResp();
			if (basicOCSPResp != null) {
				newOtherRevocationInfoFormatStore.add(DSSASN1Utils.toASN1Primitive(DSSASN1Utils.getEncoded(basicOCSPResp)));
			}
		}
		otherRevocationInfoFormatStoreBasic = new CollectionStore(newOtherRevocationInfoFormatStore);

		Store attributeCertificatesStore = cmsSignedData.getAttributeCertificates();
		Store otherRevocationInfoFormatStoreOcsp = cmsSignedData.getOtherRevocationInfo(CMSObjectIdentifiers.id_ri_ocsp_response);

		final CMSSignedDataBuilder cmsSignedDataBuilder = new CMSSignedDataBuilder(certificateVerifier);
		cmsSignedData = cmsSignedDataBuilder.regenerateCMSSignedData(cmsSignedData, detachedContents, certificatesStore, attributeCertificatesStore, crlsStore,
				otherRevocationInfoFormatStoreBasic, otherRevocationInfoFormatStoreOcsp);
		return cmsSignedData;
	}

	/**
	 * @return the a copy of x509crl as a X509CRLHolder
	 */
	private X509CRLHolder getX509CrlHolder(CRLToken crlToken) {
		try (InputStream is = crlToken.getCRLStream()) {
			return new X509CRLHolder(is);
		} catch (IOException e) {
			throw new DSSException("Unable to convert X509CRL to X509CRLHolder", e);
		}
	}

}
