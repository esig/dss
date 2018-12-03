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
package eu.europa.esig.dss.cades;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificate;
import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signingCertificateV2;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;

public final class CMSUtils {

	private static final Logger LOG = LoggerFactory.getLogger(CMSUtils.class);

	private CMSUtils() {
	}

	/**
	 * Returns the ASN.1 encoded representation of {@code CMSSignedData}.
	 *
	 * @param data
	 *             the CMSSignedData to be encoded
	 * @return the DER encoded CMSSignedData
	 */
	public static byte[] getEncoded(final CMSSignedData data) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			DEROutputStream deros = new DEROutputStream(baos);
			deros.writeObject(data.toASN1Structure());
			deros.close();
			return baos.toByteArray();
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method generate {@code CMSSignedData} using the provided #{@code CMSSignedDataGenerator}, the content and
	 * the indication if the content should be encapsulated.
	 *
	 * @param generator
	 * @param content
	 * @param encapsulate
	 * @return
	 */
	public static CMSSignedData generateCMSSignedData(final CMSSignedDataGenerator generator, final CMSTypedData content, final boolean encapsulate) {
		try {
			return generator.generate(content, encapsulate);
		} catch (CMSException e) {
			throw new DSSException(e);
		}
	}

	public static CMSSignedData generateDetachedCMSSignedData(final CMSSignedDataGenerator generator, final CMSProcessableByteArray content)
			throws DSSException {
		return generateCMSSignedData(generator, content, false);
	}

	/**
	 * @param signerInformation
	 *            {@code SignerInformation}
	 * @return {@code DERTaggedObject} representing the signed attributes
	 */
	public static DERTaggedObject getDERSignedAttributes(final SignerInformation signerInformation) {
		try {
			final byte[] encodedSignedAttributes = signerInformation.getEncodedSignedAttributes();
			if (encodedSignedAttributes == null) {
				return null;
			}
			final ASN1Set asn1Set = DSSASN1Utils.toASN1Primitive(encodedSignedAttributes);
			return new DERTaggedObject(false, 0, asn1Set);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns the signed content extracted from a CMSTypedData
	 * 
	 * @param cmsTypedData
	 *            {@code CMSTypedData} cannot be null
	 * @return the signed content extracted from {@code CMSTypedData}
	 */
	public static byte[] getSignedContent(final CMSTypedData cmsTypedData) {
		if (cmsTypedData == null) {
			throw new DSSException("CMSTypedData is null (should be a detached signature)");
		}
		try (ByteArrayOutputStream originalDocumentData = new ByteArrayOutputStream()) {
			cmsTypedData.write(originalDocumentData);
			return originalDocumentData.toByteArray();
		} catch (CMSException | IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns the existing unsigned attributes or a new empty attributes hashtable
	 *
	 * @param signerInformation
	 *            the signer information
	 * @return the existing unsigned attributes or an empty attributes hashtable
	 */
	public static AttributeTable getUnsignedAttributes(final SignerInformation signerInformation) {
		final AttributeTable unsignedAttributes = signerInformation.getUnsignedAttributes();
		return DSSASN1Utils.emptyIfNull(unsignedAttributes);
	}

	/**
	 * This method returns the existing signed attributes or a new empty attributes hashtable
	 *
	 * @param signerInformation
	 *            the signer information
	 * @return the existing signed attributes or an empty attributes {@code Hashtable}
	 */
	public static AttributeTable getSignedAttributes(final SignerInformation signerInformation) {
		final AttributeTable signedAttributes = signerInformation.getSignedAttributes();
		return DSSASN1Utils.emptyIfNull(signedAttributes);
	}

	/**
	 * This method returns an AttributeTable parsed from ASN.1 encoded representation
	 *
	 * @param encodedAttributes
	 *            ASN.1 encoded AttributesTable
	 * @return AttributeTable created from given encodedAttributes
	 */
	public static AttributeTable getAttributesFromByteArray(final byte[] encodedAttributes) {
		DLSet dlSet;
		try (ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(encodedAttributes))) {
			dlSet = (DLSet) asn1InputStream.readObject();
		} catch (IOException e) {
			throw new DSSException("Error while reading ASN.1 encoded attributes", e);
		}
		return new AttributeTable(dlSet);
	}

	/**
	 * This method allows to create a {@code BasicOCSPResp} from a {@code DERSequence}.
	 * The value for response SHALL be the DER encoding of BasicOCSPResponse (RFC 2560).
	 *
	 * @param derSequence
	 *            {@code DERSequence} to convert to {@code BasicOCSPResp}
	 * @return {@code BasicOCSPResp}
	 */
	public static BasicOCSPResp getBasicOcspResp(final DERSequence derSequence) {
		BasicOCSPResp basicOCSPResp = null;
		try {
			final BasicOCSPResponse basicOcspResponse = BasicOCSPResponse.getInstance(derSequence);
			basicOCSPResp = new BasicOCSPResp(basicOcspResponse);
		} catch (Exception e) {
			LOG.error("Impossible to create BasicOCSPResp from DERSequence!", e);
		}
		return basicOCSPResp;
	}

	/**
	 * This method allows to create a {@code OCSPResp} from a {@code DERSequence}.
	 *
	 * @param derSequence
	 *            {@code DERSequence} to convert to {@code OCSPResp}
	 * @return {@code OCSPResp}
	 */
	public static OCSPResp getOcspResp(final DERSequence derSequence) {
		OCSPResp ocspResp = null;
		try {
			final OCSPResponse ocspResponse = OCSPResponse.getInstance(derSequence);
			ocspResp = new OCSPResp(ocspResponse);
		} catch (Exception e) {
			LOG.error("Impossible to create OCSPResp from DERSequence!", e);
		}
		return ocspResp;
	}

	/**
	 * This method returns the {@code BasicOCSPResp} from a {@code OCSPResp}.
	 *
	 * @param ocspResp
	 *            {@code OCSPResp} to analysed
	 * @return
	 */
	public static BasicOCSPResp getBasicOcspResp(final OCSPResp ocspResp) {
		BasicOCSPResp basicOCSPResp = null;
		try {
			final Object responseObject = ocspResp.getResponseObject();
			if (responseObject instanceof BasicOCSPResp) {
				basicOCSPResp = (BasicOCSPResp) responseObject;
			} else {
				LOG.warn("Unknown OCSP response type: {}", responseObject.getClass());
			}
		} catch (OCSPException e) {
			LOG.error("Impossible to process OCSPResp!", e);
		}
		return basicOCSPResp;
	}

	/**
	 * Method to add signing certificate to ASN.1 DER encoded signed attributes. Certificate
	 * will be added as either signing-certificate or signing-certificate-v2 attribute depending
	 * on digest algorithm being used.
	 *
	 * @param signedAttributes
	 *            Signed attributes to append signing certificate to
	 * @param digestAlgorithm
	 *            the digest algorithm to be used
	 * @param signingToken
	 *            The signing certificate to be append
	 */
	public static void addSigningCertificateAttribute(final ASN1EncodableVector signedAttributes, final DigestAlgorithm digestAlgorithm,
			CertificateToken signingToken) {

		final IssuerSerial issuerSerial = DSSASN1Utils.getIssuerSerial(signingToken);

		final byte[] certHash = signingToken.getDigest(digestAlgorithm);
		if (LOG.isDebugEnabled()) {
			LOG.debug("Adding Certificate Hash {} with algorithm {}", Utils.toHex(certHash), digestAlgorithm.getName());
		}

		Attribute attribute = null;
		if (digestAlgorithm == DigestAlgorithm.SHA1) {
			final ESSCertID essCertID = new ESSCertID(certHash, issuerSerial);
			SigningCertificate signingCertificate = new SigningCertificate(essCertID);
			attribute = new Attribute(id_aa_signingCertificate, new DERSet(signingCertificate));
		} else {
			ESSCertIDv2 essCertIdv2 = null;
			if (DigestAlgorithm.SHA256 == digestAlgorithm) {
				// SHA-256 is default
				essCertIdv2 = new ESSCertIDv2(null, certHash, issuerSerial);
			} else {
				essCertIdv2 = new ESSCertIDv2(DSSASN1Utils.getAlgorithmIdentifier(digestAlgorithm), certHash, issuerSerial);
			}
			SigningCertificateV2 signingCertificateV2 = new SigningCertificateV2(essCertIdv2);
			attribute = new Attribute(id_aa_signingCertificateV2, new DERSet(signingCertificateV2));
		}
		signedAttributes.add(attribute);
	}

}
