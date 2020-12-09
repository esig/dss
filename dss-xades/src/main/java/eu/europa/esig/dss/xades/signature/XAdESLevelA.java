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

import org.w3c.dom.Element;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;

/**
 * Holds level A aspects of XAdES
 *
 */
public class XAdESLevelA extends XAdESLevelXL {

	/**
	 * The default constructor for XAdESLevelA.
	 *
	 * @param certificateVerifier {@link CertificateVerifier}
	 * */
	public XAdESLevelA(CertificateVerifier certificateVerifier) {
		super(certificateVerifier);
	}

	/**
	 * Adds the ArchiveTimeStamp element which is an unsigned property qualifying the signature. The hash sent to the TSA
	 * (messageImprint) is computed on the XAdES-X-L form of the electronic signature and the signed data objects.<br>
	 *
	 * A XAdES-A form MAY contain several ArchiveTimeStamp elements.
	 *
	 * @see XAdESLevelXL#extendSignatureTag()
	 */
	@Override
	protected void extendSignatureTag() throws DSSException {

		/* Up to -XL */
		super.extendSignatureTag();
		Element levelXLUnsignedProperties = (Element) unsignedSignaturePropertiesDom.cloneNode(true);

		xadesSignature.checkSignatureIntegrity();

		final XAdESTimestampParameters archiveTimestampParameters = params.getArchiveTimestampParameters();
		final String canonicalizationMethod = archiveTimestampParameters.getCanonicalizationMethod();
		final byte[] data = xadesSignature.getTimestampSource().getArchiveTimestampData(canonicalizationMethod);
		final DigestAlgorithm timestampDigestAlgorithm = archiveTimestampParameters.getDigestAlgorithm();
		final byte[] digestBytes = DSSUtils.digest(timestampDigestAlgorithm, data);
		createXAdESTimeStampType(TimestampType.ARCHIVE_TIMESTAMP, canonicalizationMethod, digestBytes);
		
		unsignedSignaturePropertiesDom = indentIfPrettyPrint(unsignedSignaturePropertiesDom, levelXLUnsignedProperties);
	}
}
