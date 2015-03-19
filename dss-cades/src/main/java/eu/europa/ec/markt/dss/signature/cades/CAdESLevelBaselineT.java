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
package eu.europa.ec.markt.dss.signature.cades;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.CAdESSignatureParameters;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * This class holds the CAdES-T signature profile; it supports the inclusion of the mandatory unsigned
 * id-aa-signatureTimeStampToken attribute as specified in ETSI TS 101 733 V1.8.1, clause 6.1.1.
 *
 *
 */

public class CAdESLevelBaselineT extends CAdESSignatureExtension {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESLevelBaselineT.class);
	final CertificateVerifier certificateVerifier;

	public CAdESLevelBaselineT(TSPSource signatureTsa, CertificateVerifier certificateVerifier, boolean onlyLastCMSSignature) {

		super(signatureTsa, onlyLastCMSSignature);
		this.certificateVerifier = certificateVerifier;
	}

	@Override
	protected SignerInformation extendCMSSignature(CMSSignedData signedData, SignerInformation signerInformation, CAdESSignatureParameters parameters)  throws DSSException {

		final CAdESSignature cadesSignature = new CAdESSignature(signedData, signerInformation);
		cadesSignature.setDetachedContents(parameters.getDetachedContent());
		assertExtendSignaturePossible(cadesSignature);

		AttributeTable unsignedAttributes = CAdESSignature.getUnsignedAttributes(signerInformation);
		unsignedAttributes = addSignatureTimestampAttribute(signerInformation, unsignedAttributes, parameters);

		return SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
	}

	/**
	 * @param cadesSignature
	 */
	 protected void assertExtendSignaturePossible(CAdESSignature cadesSignature) throws DSSException {

		 final String exceptionMessage = "Cannot extend signature. The signedData is already extended with [%s].";
		 if (cadesSignature.isDataForSignatureLevelPresent(SignatureLevel.CAdES_BASELINE_LTA)) {
			 throw new DSSException(String.format(exceptionMessage, "CAdES LTA"));
		 }
		 AttributeTable unsignedAttributes = CAdESSignature.getUnsignedAttributes(cadesSignature.getSignerInformation());
		 if (unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp) != null) {
			 throw new DSSException(String.format(exceptionMessage, PKCSObjectIdentifiers.id_aa_ets_escTimeStamp.getId()));
		 }
	 }

	 private AttributeTable addSignatureTimestampAttribute(SignerInformation signerInformation, AttributeTable unsignedAttributes, CAdESSignatureParameters parameters) {

		 ASN1Object signatureTimeStamp = getTimeStampAttributeValue(signatureTsa, signerInformation.getSignature(), parameters);
		 return unsignedAttributes.add(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, signatureTimeStamp);
	 }

	 public CertificateVerifier getCertificateVerifier() {
		 return certificateVerifier;
	 }

}
