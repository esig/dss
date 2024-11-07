/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.spi.signature.identifier.AbstractSignatureIdentifierBuilder;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.model.ManifestFile;
import org.bouncycastle.cms.SignerInformation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Collection;

/**
 * Builds a SignatureIdentifier for CAdES signature
 */
public class CAdESSignatureIdentifierBuilder extends AbstractSignatureIdentifierBuilder {

	private static final long serialVersionUID = -7828439853620987517L;

	/**
	 * The default constructor
	 *
	 * @param signature {@link CAdESSignature}
	 */
	public CAdESSignatureIdentifierBuilder(CAdESSignature signature) {
		super(signature);
	}
	
	@Override
	protected void writeSignedProperties(ByteArrayOutputStream baos) throws IOException {
		super.writeSignedProperties(baos);
		writeString(baos, getManifestFilename());
	}
	
	private String getManifestFilename() {
		ManifestFile manifestFile = signature.getManifestFile();
		if (manifestFile != null) {
			return manifestFile.getFilename();
		}
		return null;
	}

	@Override
	protected Integer getCounterSignaturePosition(AdvancedSignature masterSignature) {
		CAdESSignature cadesSignature = (CAdESSignature) signature;
		CAdESSignature cadesMasterSignature = (CAdESSignature) masterSignature;
		
		return count(cadesMasterSignature.getCounterSignatureStore().getSigners(), cadesSignature.getSignerInformation());
	}

	@Override
	protected Integer getSignaturePosition() {
		CAdESSignature cadesSignature = (CAdESSignature) signature;
		
		return count(cadesSignature.getCmsSignedData().getSignerInfos().getSigners(), cadesSignature.getSignerInformation());
	}
	
	private Integer count(Collection<SignerInformation> signerInformationStore, SignerInformation currentSignerInformation) {
		int counter = 0;
		for (SignerInformation signerInformation : signerInformationStore) {
			// compare by memory to avoid matching signers with identical content
			if (currentSignerInformation == signerInformation) {
				break;
			}
			counter++;
		}
		
		return counter;
	}

}
