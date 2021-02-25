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
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.ValidationContext;
import eu.europa.esig.dss.validation.ValidationDataForInclusion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

/**
 * Holds level LTA aspects of XAdES
 *
 */
public class XAdESLevelBaselineLTA extends XAdESLevelBaselineLT {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESLevelBaselineLTA.class);

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
	 */
	@Override
	protected void extendSignatureTag() throws DSSException {

		// check if -LT is present
		super.extendSignatureTag();
		
		assertExtendSignatureToLTAPossible();
		
		Element levelLTUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);
		if (xadesSignature.hasLTAProfile()) {
			checkSignatureIntegrity();

			// must be executed before data removing
			final ValidationContext validationContext = xadesSignature.getSignatureValidationContext(certificateVerifier);
			String indent = removeLastTimestampValidationData();
			
			ValidationDataForInclusion validationDataForInclusion = getValidationDataForInclusion(validationContext);
			incorporateTimestampValidationData(validationDataForInclusion, indent);
		}
		incorporateArchiveTimestamp();
		
		unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelLTUnsignedProperties);
	}

	private void assertExtendSignatureToLTAPossible() {
		if (SignatureLevel.XAdES_BASELINE_LTA.equals(params.getSignatureLevel())) {
			assertDetachedDocumentsContainBinaries();
		}
	}
	
}
