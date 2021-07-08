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

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.SignerInformation;

/**
 * Represents the CAdES Signed attributes
 */
public class CAdESSignedAttributes extends CAdESSigProperties {

	private static final long serialVersionUID = 7180428714024547376L;

	/**
	 * The default constructor
	 *
	 * @param attributeTable {@link AttributeTable} signed attributes table
	 */
	CAdESSignedAttributes(AttributeTable attributeTable) {
		super(attributeTable);
	}

	/**
	 * Builds the {@code CAdESSignedAttributes} from a {@code SignerInformation}
	 *
	 * @param signerInformation {@link SignerInformation} to build {@link CAdESSignedAttributes} from
	 * @return {@link CAdESSignedAttributes}
	 */
	public static CAdESSignedAttributes build(SignerInformation signerInformation) {
		return new CAdESSignedAttributes(signerInformation.getSignedAttributes());
	}

}
