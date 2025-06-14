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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.signature.identifier.AbstractSignatureIdentifierBuilder;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Builds a DSS identifier for a XAdES signature
 */
public class XAdESSignatureIdentifierBuilder extends AbstractSignatureIdentifierBuilder {

	private static final long serialVersionUID = 6174322691822584700L;

	/**
	 * Default constructor
	 *
	 * @param signature {@link XAdESSignature}
	 */
	public XAdESSignatureIdentifierBuilder(XAdESSignature signature) {
		super(signature);
	}

	@Override
	protected Integer getCounterSignaturePosition(AdvancedSignature masterSignature) {
		XAdESSignature xadesMasterSignature = (XAdESSignature) masterSignature;
		XAdESSignature xadesSignature = (XAdESSignature) signature;
		
		int counter = 0;
		for (AdvancedSignature counterSignature : xadesMasterSignature.getCounterSignatures()) {
			XAdESSignature xadesCounterSignature = (XAdESSignature) counterSignature;
			if (xadesSignature.getSignatureElement() == xadesCounterSignature.getSignatureElement()) {
				break;
			}
			++counter;
		}
		
		return counter;
	}

	@Override
	protected Integer getSignaturePosition() {
		XAdESSignature xadesSignature = (XAdESSignature) signature;
		Element signatureElement = xadesSignature.getSignatureElement();
		Document document = signatureElement.getOwnerDocument();
		final NodeList signatureNodeList = DSSXMLUtils.getAllSignaturesExceptCounterSignatures(document);
		
		int counter = 0;
		while (counter < signatureNodeList.getLength()) {
			if (signatureElement == signatureNodeList.item(counter)) {
				break;
			}
			++counter;
		}
		
		return counter;
	}

	@Override
	protected Object getSignatureFilePosition() {
		String signatureFilename = signature.getFilename();
		if (Utils.isStringNotEmpty(signatureFilename) && signatureFilename.startsWith(META_INF_FOLDER)) {
			return signatureFilename;
		}
		return Utils.EMPTY_STRING;
	}

}
