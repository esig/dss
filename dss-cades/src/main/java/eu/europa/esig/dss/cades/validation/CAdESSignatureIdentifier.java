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
package eu.europa.esig.dss.cades.validation;

import java.util.Collection;

import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;

import eu.europa.esig.dss.model.identifier.TokenIdentifier;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.SignatureIdentifier;

public final class CAdESSignatureIdentifier extends SignatureIdentifier {

	private static final long serialVersionUID = -26714442410369595L;

	public CAdESSignatureIdentifier(CAdESSignature cadesSignature) {
		super(buildBinaries(cadesSignature));
	}
	
	private static byte[] buildBinaries(CAdESSignature cadesSignature) {
		final CertificateToken certificateToken = cadesSignature.getSigningCertificateToken();
		final TokenIdentifier identifier = certificateToken == null ? null : certificateToken.getDSSId();
		
		// introduce additional variables in order to avoid signatures with duplicate ids
		Integer uniqueInteger = getUniqueIntegerIfNeeded(cadesSignature);
		if (uniqueInteger == 0) uniqueInteger = null;
		String masterSignatureId = getMasterSignatureId(cadesSignature);
		String fileName = cadesSignature.getSignatureFilename();

		return SignatureIdentifier.buildSignatureIdentifier(cadesSignature.getSigningTime(), identifier, uniqueInteger, masterSignatureId, fileName);
	}
	
	/**
	 * Returns the related position of {@code this.signerInformation} in the cmsSignedData
	 * among signers with the same SID
	 * 
	 * @param cadesSignature {@link CAdESSignature}
	 * @return integer identifier
	 */
	private static int getUniqueIntegerIfNeeded(CAdESSignature cadesSignature) {
		Collection<SignerInformation> signerInformations;
		SignerId signerId = cadesSignature.getSignerId();
		if (cadesSignature.isCounterSignature()) {
			signerInformations = cadesSignature.getSignerInformation().getCounterSignatures().getSigners(signerId);
		} else {
			signerInformations = cadesSignature.getCmsSignedData().getSignerInfos().getSigners(signerId);
		}
		int counter = 0;
		for (SignerInformation currentSignerInformation : signerInformations) {
			if (cadesSignature.getSignerInformation() == currentSignerInformation) {
				break;
			}
			counter++;
		}
		return counter;
	}
	
	/**
	 * Returns Id of the {@code masterSignature} if exists, otherwise returns NULL
	 * 
	 * @param cadesSignature {@link CAdESSignature}
	 * @return {@link String} masterSignature id
	 */
	private static String getMasterSignatureId(CAdESSignature cadesSignature) {
		AdvancedSignature masterSignature = cadesSignature.getMasterSignature();
		if (masterSignature != null) {
			return masterSignature.getId();
		}
		return null;
	}

}
