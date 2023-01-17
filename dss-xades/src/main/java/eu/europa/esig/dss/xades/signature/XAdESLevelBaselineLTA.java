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
package eu.europa.esig.dss.xades.signature;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.validation.AdvancedSignature;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationData;
import eu.europa.esig.dss.validation.ValidationDataContainer;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import org.w3c.dom.Element;

import java.util.List;

/**
 * Holds level LTA aspects of XAdES
 *
 */
public class XAdESLevelBaselineLTA extends XAdESLevelBaselineLT {

	/**
	 * The default constructor for XAdESLevelBaselineLTA.
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 */
	public XAdESLevelBaselineLTA(final CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * Adds the ArchiveTimeStamp element which is an unsigned property qualifying the signature. The hash sent to the
	 * TSA
	 * (messageImprint) is computed on the XAdES-LT form of the electronic signature and the signed data objects.<br>
	 *
	 * A XAdES-LTA form MAY contain several ArchiveTimeStamp elements.
	 *
	 * @see XAdESLevelBaselineLT#extendSignatures(List)
	 */
	@Override
	protected void extendSignatures(List<AdvancedSignature> signatures) {
		super.extendSignatures(signatures);

		boolean addTimestampValidationData = false;

		for (AdvancedSignature signature : signatures) {
			initializeSignatureBuilder((XAdESSignature) signature);
			assertSignatureValid(signature);

			if (xadesSignature.hasLTAProfile()) {
				addTimestampValidationData = true;
			}
		}

		// Perform signature validation
		ValidationDataContainer validationDataContainer = null;
		if (addTimestampValidationData) {
			validationDataContainer = documentValidator.getValidationData(signatures);
		}

		// Append LTA-level (+ ValidationData)
		for (AdvancedSignature signature : signatures) {
			initializeSignatureBuilder((XAdESSignature) signature);

			assertExtendSignatureToLTAPossible();

			Element levelLTUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

			if (xadesSignature.hasLTAProfile() && addTimestampValidationData) {
				String indent = removeLastTimestampValidationData();
				ValidationData validationDataForInclusion = validationDataContainer.getCompleteValidationDataForSignature(signature);
				incorporateTimestampValidationData(validationDataForInclusion, indent);
			}

			incorporateArchiveTimestamp();
			unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelLTUnsignedProperties);
		}
	}

	private void assertExtendSignatureToLTAPossible() {
		if (SignatureLevel.XAdES_BASELINE_LTA.equals(params.getSignatureLevel())) {
			assertDetachedDocumentsContainBinaries();
		}
	}
	
}
