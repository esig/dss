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
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

/**
 * This class holds the CAdES-T signature profile; it supports the inclusion of the mandatory unsigned
 * id-aa-signatureTimeStampToken attribute as specified in ETSI TS 101 733 V1.8.1, clause 6.1.1.
 *
 */
public class CAdESLevelBaselineT extends CAdESSignatureExtension {

	/**
	 * The default constructor
	 *
	 * @param tspSource {@link TSPSource} to request a timestamp
	 */
	public CAdESLevelBaselineT(TSPSource tspSource) {
		super(tspSource);
	}

	@Override
	protected SignerInformation extendSignerInformation(CMSSignedData signedData, SignerInformation signerInformation, CAdESSignatureParameters parameters) {
		final CAdESSignature cadesSignature = newCAdESSignature(signedData, signerInformation, parameters.getDetachedContents());
		assertExtendSignatureLevelTPossible(cadesSignature);

		AttributeTable unsignedAttributes = CMSUtils.getUnsignedAttributes(signerInformation);
		unsignedAttributes = addSignatureTimestampAttribute(signerInformation, unsignedAttributes, parameters);

		return SignerInformation.replaceUnsignedAttributes(signerInformation, unsignedAttributes);
	}

	/**
	 * Checks if the signature extension is possible
	 *
	 * @param cadesSignature {@link CAdESSignature}
	 */
	private void assertExtendSignatureLevelTPossible(CAdESSignature cadesSignature) {
		final String exceptionMessage = "Cannot extend signature. The signedData is already extended with [%s].";
		if (cadesSignature.hasLTAProfile()) {
			throw new DSSException(String.format(exceptionMessage, "CAdES LTA"));
		}
		AttributeTable unsignedAttributes = CMSUtils.getUnsignedAttributes(cadesSignature.getSignerInformation());
		if (unsignedAttributes.get(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp) != null) {
			throw new DSSException(String.format(exceptionMessage, PKCSObjectIdentifiers.id_aa_ets_escTimeStamp.getId()));
		}
	}

	private AttributeTable addSignatureTimestampAttribute(SignerInformation signerInformation, AttributeTable unsignedAttributes,
			CAdESSignatureParameters parameters) {
		final DigestAlgorithm timestampDigestAlgorithm = parameters.getSignatureTimestampParameters().getDigestAlgorithm();
		ASN1Object signatureTimeStamp = getTimeStampAttributeValue(signerInformation.getSignature(), timestampDigestAlgorithm);
		return unsignedAttributes.add(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, signatureTimeStamp);
	}

}
