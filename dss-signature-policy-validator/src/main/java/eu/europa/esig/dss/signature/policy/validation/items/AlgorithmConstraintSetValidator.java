/*******************************************************************************
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
 ******************************************************************************/
package eu.europa.esig.dss.signature.policy.validation.items;

import java.util.List;

import org.bouncycastle.cms.SignerInformation;

import eu.europa.esig.dss.DSSPKUtils;
import eu.europa.esig.dss.cades.validation.CAdESSignature;
import eu.europa.esig.dss.signature.policy.AlgAndLength;
import eu.europa.esig.dss.x509.CertificateToken;

public class AlgorithmConstraintSetValidator implements ItemValidator {
	
	private List<AlgAndLength> algAndLengthRestrictions;
	private String encryptionAlgOID;
	private int keySize;

	public AlgorithmConstraintSetValidator(List<AlgAndLength> algAndLengthRestrictions, CAdESSignature signature) {
		this.algAndLengthRestrictions = algAndLengthRestrictions;
		extractAlgorithmAngLength(signature);
	}

	private void extractAlgorithmAngLength(CAdESSignature signature) {
		SignerInformation signerInformation = signature.getSignerInformation();
		CertificateToken signingCertificateToken = signature.getSigningCertificateToken();
		
		encryptionAlgOID = signerInformation.getEncryptionAlgOID();
		keySize = signingCertificateToken == null? 0: DSSPKUtils.getPublicKeySize(signingCertificateToken.getPublicKey());
	}

	@Override
	public boolean validate() {
		for (AlgAndLength algAndLength : algAndLengthRestrictions) {
			if (algAndLength.getAlgID().equals(encryptionAlgOID) && algAndLength.getMinKeyLength() <= keySize) {
				return true;
			}
		}
		return false;
	}

	@Override
	public String getErrorDetail() {
		return null;
	}

}
