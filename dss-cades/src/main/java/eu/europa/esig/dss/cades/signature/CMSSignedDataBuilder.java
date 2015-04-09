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

import static org.bouncycastle.asn1.cms.CMSObjectIdentifiers.id_ri_ocsp_response;
import static org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_basic;

import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.Store;

import eu.europa.esig.dss.ChainCertificate;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.x509.CertificateSource;
import eu.europa.esig.dss.x509.CertificateToken;

/**
 *
 *
 *
 *
 *
 *
 */
public class CMSSignedDataBuilder {

	private CertificateVerifier certificateVerifier;

	/**
	 * This is the default constructor for {@code CMSSignedDataGeneratorBuilder}. The {@code CertificateVerifier} is used to find the trusted certificates.
	 *
	 * @param certificateVerifier {@code CertificateVerifier} provides information on the sources to be used in the validation process in the context of a signature.
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
	 * ---> CMS SignedData Version is handled automatically by BouncyCastle.
	 *
	 * @param parameters                 set of the driving signing parameters
	 * @param contentSigner              the contentSigned to get the hash of the data to be signed
	 * @param signerInfoGeneratorBuilder true if the unsigned attributes must be included
	 * @param originalSignedData         the original signed data if extending an existing signature. null otherwise.
	 * @return the bouncycastle signed data generator which signs the document and adds the required signed and unsigned CMS attributes
	 * @throws eu.europa.esig.dss.DSSException
	 */
	protected CMSSignedDataGenerator createCMSSignedDataGenerator(final CAdESSignatureParameters parameters, final ContentSigner contentSigner,
			final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder,
			final CMSSignedData originalSignedData) throws DSSException {
		try {

			final CertificateToken signingCertificate = parameters.getSigningCertificate();

			final CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

			final X509CertificateHolder certHolder = signingCertificate.getX509CertificateHolder();
			final SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(contentSigner, certHolder);

			generator.addSignerInfoGenerator(signerInfoGenerator);

			final Set<CertificateToken> newCertificateChain = new HashSet<CertificateToken>();

			if (originalSignedData != null) {

				generator.addSigners(originalSignedData.getSignerInfos());
				generator.addAttributeCertificates(originalSignedData.getAttributeCertificates());
				generator.addCRLs(originalSignedData.getCRLs());
				generator.addOtherRevocationInfo(id_pkix_ocsp_basic, originalSignedData.getOtherRevocationInfo(id_pkix_ocsp_basic));
				generator.addOtherRevocationInfo(id_ri_ocsp_response, originalSignedData.getOtherRevocationInfo(id_ri_ocsp_response));

				final Store certificates = originalSignedData.getCertificates();
				final Collection<X509CertificateHolder> certificatesMatches = certificates.getMatches(null);
				for (final X509CertificateHolder certificatesMatch : certificatesMatches) {

					final CertificateToken x509Certificate = DSSUtils.getCertificate(certificatesMatch);
					newCertificateChain.add(x509Certificate);
				}
			}
			final List<ChainCertificate> certificateChain = parameters.getCertificateChain();
			for (final ChainCertificate chainCertificate : certificateChain) {

				final CertificateToken x509Certificate = chainCertificate.getX509Certificate();
				newCertificateChain.add(x509Certificate);
			}
			final boolean trustAnchorBPPolicy = parameters.bLevel().isTrustAnchorBPPolicy();
			final Store jcaCertStore = getJcaCertStore(newCertificateChain, trustAnchorBPPolicy);
			generator.addCertificates(jcaCertStore);
			return generator;
		} catch (CMSException e) {
			throw new DSSException(e);
		} catch (OperatorCreationException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * @param parameters                the parameters of the signature containing values for the attributes
	 * @param includeUnsignedAttributes true if the unsigned attributes must be included
	 * @return a SignerInfoGeneratorBuilder that generate the signed and unsigned attributes according to the CAdESLevelBaselineB
	 */
	SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder(final CAdESSignatureParameters parameters, final boolean includeUnsignedAttributes) {

		final CAdESLevelBaselineB cadesProfile = new CAdESLevelBaselineB();
		final AttributeTable signedAttributes = cadesProfile.getSignedAttributes(parameters);

		AttributeTable unsignedAttributes = null;
		if (includeUnsignedAttributes) {
			unsignedAttributes = cadesProfile.getUnsignedAttributes();
		}
		return getSignerInfoGeneratorBuilder(signedAttributes, unsignedAttributes);
	}

	/**
	 * @param signedAttributes   the signedAttributes
	 * @param unsignedAttributes the unsignedAttributes
	 * @return a SignerInfoGeneratorBuilder that generate the signed and unsigned attributes according to the parameters
	 */
	private SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder(AttributeTable signedAttributes, AttributeTable unsignedAttributes) {

		if ((signedAttributes != null) && (signedAttributes.size() == 0)) {
			signedAttributes = null;
		}
		final DefaultSignedAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributes);
		if ((unsignedAttributes != null) && (unsignedAttributes.size() == 0)) {
			unsignedAttributes = null;
		}
		final SimpleAttributeTableGenerator unsignedAttributeGenerator = new SimpleAttributeTableGenerator(unsignedAttributes);

		return getSignerInfoGeneratorBuilder(signedAttributeGenerator, unsignedAttributeGenerator);
	}

	/**
	 * @param signedAttributeGenerator   the signedAttribute generator
	 * @param unsignedAttributeGenerator the unsignedAttribute generator
	 * @return a SignerInfoGeneratorBuilder that generate the signed and unsigned attributes according to the parameters
	 */
	private SignerInfoGeneratorBuilder getSignerInfoGeneratorBuilder(DefaultSignedAttributeTableGenerator signedAttributeGenerator,
			SimpleAttributeTableGenerator unsignedAttributeGenerator) {

		final DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();
		SignerInfoGeneratorBuilder sigInfoGeneratorBuilder = new SignerInfoGeneratorBuilder(digestCalculatorProvider);
		sigInfoGeneratorBuilder.setSignedAttributeGenerator(signedAttributeGenerator);
		sigInfoGeneratorBuilder.setUnsignedAttributeGenerator(unsignedAttributeGenerator);
		return sigInfoGeneratorBuilder;
	}

	/**
	 * The order of the certificates is important, the fist one must be the signing certificate.
	 *
	 * @return a store with the certificate chain of the signing certificate. The {@code Collection} is unique.
	 * @throws CertificateEncodingException
	 */
	private JcaCertStore getJcaCertStore(final Collection<CertificateToken> certificateChain, boolean trustAnchorBPPolicy) {

		try {

			final Collection<X509Certificate> certs = new ArrayList<X509Certificate>();
			for (final CertificateToken certificateInChain : certificateChain) {

				// CAdES-Baseline-B: do not include certificates found in the trusted list
				if (trustAnchorBPPolicy) {

					final X500Principal subjectX500Principal = certificateInChain.getSubjectX500Principal();
					final CertificateSource trustedCertSource = certificateVerifier.getTrustedCertSource();
					if (trustedCertSource != null) {
						if (!trustedCertSource.get(subjectX500Principal).isEmpty()) {
							continue;
						}
					}
				}
				certs.add(certificateInChain.getCertificate());
			}
			return new JcaCertStore(certs);
		} catch (CertificateEncodingException e) {
			throw new DSSException(e);
		}
	}

	protected CMSSignedData regenerateCMSSignedData(CMSSignedData cmsSignedData, CAdESSignatureParameters parameters, Store certificatesStore, Store attributeCertificatesStore,
			Store crlsStore, Store otherRevocationInfoFormatStoreBasic, Store otherRevocationInfoFormatStoreOcsp) {
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
				final InputStream inputStream = parameters.getDetachedContent().openStream();
				final CMSProcessableByteArray content = new CMSProcessableByteArray(DSSUtils.toByteArray(inputStream));
				IOUtils.closeQuietly(inputStream);
				cmsSignedData = cmsSignedDataGenerator.generate(content, encapsulate);
			} else {
				cmsSignedData = cmsSignedDataGenerator.generate(cmsSignedData.getSignedContent(), encapsulate);
			}
			return cmsSignedData;
		} catch (CMSException e) {
			throw new DSSException(e);
		}
	}

	//TODO Vincent: regeneration of SignedData -> Content-TS
}
