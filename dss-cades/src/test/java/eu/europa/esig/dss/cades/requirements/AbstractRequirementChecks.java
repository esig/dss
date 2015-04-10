package eu.europa.esig.dss.cades.requirements;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.cert.X509Certificate;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSDocument;

public abstract class AbstractRequirementChecks {

	private static final Logger logger = LoggerFactory.getLogger(AbstractRequirementChecks.class);

	private SignedData signedData;
	private SignerInfo signerInfo;

	@Before
	public void init() throws Exception {
		DSSDocument signedDocument = getSignedDocument();

		ASN1InputStream asn1sInput = new ASN1InputStream(signedDocument.getBytes());
		ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();
		assertEquals(2, asn1Seq.size());
		ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(asn1Seq.getObjectAt(0));
		assertEquals(PKCSObjectIdentifiers.signedData, oid);

		ASN1TaggedObject taggedObj = DERTaggedObject.getInstance(asn1Seq.getObjectAt(1));
		signedData = SignedData.getInstance(taggedObj.getObject());

		ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
		assertEquals(1, signerInfosAsn1.size());

		signerInfo = SignerInfo.getInstance(ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0)));

		IOUtils.closeQuietly(asn1sInput);
	}

	protected abstract DSSDocument getSignedDocument() throws Exception;

	/**
	 * SignedData.certificates shall be present in B/T/LT/LTA
	 */
	@Test
	public void checkSignedDataCertificatesPresent() throws Exception {
		ASN1Set certificates = signedData.getCertificates();
		logger.info("CERTIFICATES (" + certificates.size() + ") : " + certificates);

		for (int i = 0; i < certificates.size(); i++) {
			ASN1Sequence seqCertif = ASN1Sequence.getInstance(certificates.getObjectAt(i));
			X509CertificateHolder certificateHolder = new X509CertificateHolder(seqCertif.getEncoded());
			X509Certificate certificate = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(
					certificateHolder);

			certificate.checkValidity();
		}
	}

	/**
	 * Content-type shall be present in B/T/LT/LTA
	 */
	@Test
	public void checkContentTypePresent() {
		assertTrue(isSignedAttributeFound(PKCSObjectIdentifiers.pkcs_9_at_contentType));
	}

	/**
	 * Message-digest shall be present in B/T/LT/LTA
	 */
	@Test
	public void checkMessageDigestPresent() {
		assertTrue(isSignedAttributeFound(PKCSObjectIdentifiers.pkcs_9_at_messageDigest));
	}

	/**
	 * Signing-time shall be present in B/T/LT/LTA
	 */
	@Test
	public void checkSigningTimePresent() {
		assertTrue(isSignedAttributeFound(PKCSObjectIdentifiers.pkcs_9_at_signingTime));
	}

	/**
	 *  signature-time-stamp shall be present in T/LT/LTA
	 */
	@Test
	public void checkSignatureTimeStampPresent() {
		assertTrue(isUnsignedAttributeFound(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken));
	}

	private boolean isSignedAttributeFound(ASN1ObjectIdentifier oid) {
		ASN1Set authenticatedAttributes = signerInfo.getAuthenticatedAttributes();
		for (int i = 0; i < authenticatedAttributes.size(); i++) {
			ASN1Sequence authAttrSeq = ASN1Sequence.getInstance(authenticatedAttributes.getObjectAt(i));
			ASN1ObjectIdentifier attrOid = ASN1ObjectIdentifier.getInstance(authAttrSeq.getObjectAt(0));
			if (oid.equals(attrOid)) {
				return true;
			}
		}
		return false;
	}

	private boolean isUnsignedAttributeFound(ASN1ObjectIdentifier oid) {
		ASN1Set unauthenticatedAttributes = signerInfo.getUnauthenticatedAttributes();
		for (int i = 0; i < unauthenticatedAttributes.size(); i++) {
			ASN1Sequence authAttrSeq = ASN1Sequence.getInstance(unauthenticatedAttributes.getObjectAt(i));
			ASN1ObjectIdentifier attrOid = ASN1ObjectIdentifier.getInstance(authAttrSeq.getObjectAt(0));
			if (oid.equals(attrOid)) {
				return true;
			}
		}
		return false;
	}
}
