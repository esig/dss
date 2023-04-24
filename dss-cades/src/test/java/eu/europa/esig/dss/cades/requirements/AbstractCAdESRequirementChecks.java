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
package eu.europa.esig.dss.cades.requirements;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.AbstractCAdESTestSignature;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CAdESTimestampParameters;
import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class AbstractCAdESRequirementChecks extends AbstractCAdESTestSignature {

	private static final Logger logger = LoggerFactory.getLogger(AbstractCAdESRequirementChecks.class);
	
	private DSSDocument documentToSign;
	private CAdESService service;
	private CAdESSignatureParameters signatureParameters;

	@BeforeEach
	public void init() throws Exception {
		documentToSign = new InMemoryDocument("Hello world".getBytes());
		
		service = new CAdESService(getCompleteCertificateVerifier());
		service.setTspSource(getGoodTsa());
		
		signatureParameters = new CAdESSignatureParameters();
		signatureParameters.setSigningCertificate(getSigningCert());
		signatureParameters.setCertificateChain(getCertificateChain());
		signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
	}
	
	@Override
	protected void onDocumentSigned(byte[] byteArray) {
		super.onDocumentSigned(byteArray);
		try {
			ASN1InputStream asn1sInput = new ASN1InputStream(byteArray);
			ASN1Sequence asn1Seq = (ASN1Sequence) asn1sInput.readObject();
			
			assertEquals(2, asn1Seq.size());
			ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(asn1Seq.getObjectAt(0));
			assertEquals(PKCSObjectIdentifiers.signedData, oid);

			ASN1TaggedObject taggedObj = ASN1TaggedObject.getInstance(asn1Seq.getObjectAt(1));
			SignedData signedData = SignedData.getInstance(taggedObj.getBaseObject());

			ASN1Set signerInfosAsn1 = signedData.getSignerInfos();
			assertEquals(1, signerInfosAsn1.size());

			SignerInfo signerInfo = SignerInfo.getInstance(ASN1Sequence.getInstance(signerInfosAsn1.getObjectAt(0)));

			checkSignedData(signedData);
			checkContentTypePresent(signerInfo);
			checkMessageDigestPresent(signerInfo);
			checkSigningTimePresent(signerInfo);
			checkSignatureTimeStampPresent(signerInfo);
			checkCertificateValue(signerInfo);
			checkCompleteCertificateReference(signerInfo);
			checkRevocationValues(signerInfo);
			checkCompleteRevocationReferences(signerInfo);
			checkCAdESCTimestamp(signerInfo);
			checkTimestampedCertsCrlsReferences(signerInfo);
			checkArchiveTimeStampV3(signerInfo);

			Utils.closeQuietly(asn1sInput);
		} catch (Exception e) {
			fail(e);
		}
	}

	/**
	 * SignedData shall be present in B/T/LT/LTA
	 */
	protected void checkSignedData(SignedData signedData) throws Exception {
		checkSignedDataCertificatesPresent(signedData);
	}

	/**
	 * SignedData.certificates shall be present in B/T/LT/LTA
	 */
	protected void checkSignedDataCertificatesPresent(SignedData signedData) throws Exception {
		ASN1Set certificates = signedData.getCertificates();
		logger.info("CERTIFICATES (" + certificates.size() + ") : " + certificates);
		assertTrue(certificates.size() > 0);

		for (int i = 0; i < certificates.size(); i++) {
			ASN1Sequence seqCertif = ASN1Sequence.getInstance(certificates.getObjectAt(i));
			X509CertificateHolder certificateHolder = new X509CertificateHolder(seqCertif.getEncoded());
			CertificateToken certificate = DSSASN1Utils.getCertificate(certificateHolder);
			certificate.getCertificate().checkValidity();
		}
	}

	/**
	 * SignedData.crls shall be present in LT/LTA
	 */
	protected void checkSignedDataRevocationDataPresent(SignedData signedData) throws Exception {
		ASN1Set crls = signedData.getCRLs();
		logger.info("CRLs (" + crls.size() + ") : " + crls);
		assertTrue(crls.size() > 1);

		boolean crlFound = false;
		boolean ocspFound = false;
		for (int i = 0; i < crls.size(); i++) {
			ASN1Primitive asn1Primitive = (crls.getObjectAt(i)).toASN1Primitive();
			if (asn1Primitive instanceof ASN1Sequence) {
				CRLBinary crlBinary = CRLUtils.buildCRLBinary(asn1Primitive.getEncoded());
				assertNotNull(crlBinary);
				crlFound = true;
			} else if (asn1Primitive instanceof ASN1TaggedObject) {
				ASN1TaggedObject asn1TaggedObject = ASN1TaggedObject.getInstance(asn1Primitive);
				if (asn1TaggedObject.getTagNo() == 1) {
					OtherRevocationInfoFormat infoFormat = OtherRevocationInfoFormat.getInstance(asn1TaggedObject, false);
					assertEquals(CMSObjectIdentifiers.id_ri_ocsp_response, infoFormat.getInfoFormat());

					ASN1Sequence asn1Sequence = (ASN1Sequence) infoFormat.getInfo();
					assertEquals(2, asn1Sequence.size());

					final OCSPResp ocspResp = DSSRevocationUtils.getOcspResp(asn1Sequence);
					assertNotNull(ocspResp);
					ocspFound = true;
				}
			}
		}
		assertTrue(crlFound, "CRL is not found!");
		assertTrue(ocspFound, "OCSP is not found!");
	}

	/**
	 * Content-type shall be present in B/T/LT/LTA
	 */
	protected void checkContentTypePresent(SignerInfo signerInfo) {
		assertTrue(isSignedAttributeFound(signerInfo, PKCSObjectIdentifiers.pkcs_9_at_contentType));
	}

	/**
	 * Message-digest shall be present in B/T/LT/LTA
	 */
	protected void checkMessageDigestPresent(SignerInfo signerInfo) {
		assertTrue(isSignedAttributeFound(signerInfo, PKCSObjectIdentifiers.pkcs_9_at_messageDigest));
	}

	/**
	 * Signing-time shall be present in B/T/LT/LTA
	 */
	protected void checkSigningTimePresent(SignerInfo signerInfo) {
		assertTrue(isSignedAttributeFound(signerInfo, PKCSObjectIdentifiers.pkcs_9_at_signingTime));
	}

	/**
	 * signature-time-stamp shall be present in T/LT/LTA
	 */
	protected void checkSignatureTimeStampPresent(SignerInfo signerInfo) {
		assertTrue(isUnsignedAttributeFound(signerInfo, PKCSObjectIdentifiers.id_aa_signatureTimeStampToken));
	}

	/**
	 * certificate-value shall not be present (B/T 1 or 0 ; LT/LTA 0)
	 */
	protected abstract void checkCertificateValue(SignerInfo signerInfo);

	/**
	 * complete-certificate-references shall not be present (B/T 1 or 0 ; LT/LTA 0)
	 */
	protected abstract void checkCompleteCertificateReference(SignerInfo signerInfo);

	/**
	 * revocation-values shall not be present (B/T 1 or 0 ; LT/LTA 0)
	 */
	protected abstract void checkRevocationValues(SignerInfo signerInfo);

	/**
	 * complete-revocation-references shall not be present (B/T 1 or 0 ; LT/LTA 0)
	 */
	protected abstract void checkCompleteRevocationReferences(SignerInfo signerInfo);

	/**
	 * CAdES-C-timestamp shall not be present (B/T 0+ ; LT/LTA 0)
	 */
	protected abstract void checkCAdESCTimestamp(SignerInfo signerInfo);

	/**
	 * time-stamped-certs-crls-references shall not be present (B/T 0+ ; LT/LTA 0)
	 */
	protected abstract void checkTimestampedCertsCrlsReferences(SignerInfo signerInfo);

	/**
	 * archive-time-stamp-v3 (B/T/LT 0; LTA 1+)
	 */
	protected abstract void checkArchiveTimeStampV3(SignerInfo signerInfo);

	protected boolean isSignedAttributeFound(SignerInfo signerInfo, ASN1ObjectIdentifier oid) {
		return countSignedAttribute(signerInfo, oid) > 0;
	}

	protected boolean isUnsignedAttributeFound(SignerInfo signerInfo, ASN1ObjectIdentifier oid) {
		return countUnsignedAttribute(signerInfo, oid) > 0;
	}

	protected int countSignedAttribute(SignerInfo signerInfo, ASN1ObjectIdentifier oid) {
		ASN1Set authenticatedAttributes = signerInfo.getAuthenticatedAttributes();
		return countInSet(oid, authenticatedAttributes);
	}

	protected int countUnsignedAttribute(SignerInfo signerInfo, ASN1ObjectIdentifier oid) {
		ASN1Set unauthenticatedAttributes = signerInfo.getUnauthenticatedAttributes();
		return countInSet(oid, unauthenticatedAttributes);
	}

	private int countInSet(ASN1ObjectIdentifier oid, ASN1Set set) {
		int counter = 0;
		if (set != null) {
			for (int i = 0; i < set.size(); i++) {
				ASN1Sequence attrSeq = ASN1Sequence.getInstance(set.getObjectAt(i));
				ASN1ObjectIdentifier attrOid = ASN1ObjectIdentifier.getInstance(attrSeq.getObjectAt(0));
				if (oid.equals(attrOid)) {
					counter++;
				}
			}
		}
		return counter;
	}

	@Override
	protected DSSDocument getDocumentToSign() {
		return documentToSign;
	}

	@Override
	protected DocumentSignatureService<CAdESSignatureParameters, CAdESTimestampParameters> getService() {
		return service;
	}
	
	@Override
	protected CAdESSignatureParameters getSignatureParameters() {
		return signatureParameters;
	}

	@Override
	protected String getSigningAlias() {
		return GOOD_USER;
	}
}
