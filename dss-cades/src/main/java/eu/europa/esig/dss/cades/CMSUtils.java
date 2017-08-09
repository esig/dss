package eu.europa.esig.dss.cades;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
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

public final class CMSUtils {

	private static final Logger LOG = LoggerFactory.getLogger(CMSUtils.class);

	private CMSUtils() {
	}

	/**
	 * Returns the ASN.1 encoded representation of {@code CMSSignedData}.
	 *
	 * @param data
	 * @return
	 * @throws DSSException
	 */
	public static byte[] getEncoded(final CMSSignedData data) throws DSSException {
		try {
			return data.getEncoded();
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
	 * @throws DSSException
	 */
	public static CMSSignedData generateCMSSignedData(final CMSSignedDataGenerator generator, final CMSProcessableByteArray content, final boolean encapsulate)
			throws DSSException {
		try {
			final CMSSignedData cmsSignedData = generator.generate(content, encapsulate);
			return cmsSignedData;
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
	 * @throws DSSException
	 *             in case of a decoding problem
	 */
	public static DERTaggedObject getDERSignedAttributes(final SignerInformation signerInformation) throws DSSException {
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
		if (unsignedAttributes == null) {
			return new AttributeTable(new Hashtable<ASN1ObjectIdentifier, Attribute>());
		} else {
			return unsignedAttributes;
		}
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
		if (signedAttributes == null) {
			return new AttributeTable(new Hashtable<ASN1ObjectIdentifier, Attribute>());
		} else {
			return signedAttributes;
		}
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
	public static BasicOCSPResp getBasicOCSPResp(final OCSPResp ocspResp) {
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

}
