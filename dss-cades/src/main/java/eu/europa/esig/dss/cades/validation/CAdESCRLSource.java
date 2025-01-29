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

import eu.europa.esig.dss.cms.CMS;
import eu.europa.esig.dss.spi.x509.CMSCRLSource;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSSignedData;

/**
 * The CRL source for a CAdES signature
 */
@SuppressWarnings("serial")
public class CAdESCRLSource extends CMSCRLSource {

	/**
	 * The default constructor
	 *
	 * @param cmsSignedData {@link CMSSignedData} of the CAdES signature
	 * @param unsignedAttributes {@link AttributeTable} the corresponding unsigned properties if present
	 * @deprecated since DSS 6.3. Please use {@code new CAdESCRLSource(CMS cms, AttributeTable unsignedAttributes)}
	 *             constructor instead.
	 */
	@Deprecated
	public CAdESCRLSource(CMSSignedData cmsSignedData, AttributeTable unsignedAttributes) {
		super(cmsSignedData, unsignedAttributes);
	}

	/**
	 * Creates a CAdES CRL source from a {@code CMS} and the related {@code unsignedAttributes} of the signer
	 *
	 * @param cms {@link CMS}
	 * @param unsignedAttributes {@link AttributeTable}
	 */
	public CAdESCRLSource(final CMS cms, final AttributeTable unsignedAttributes) {
		super(cms.getCRLs(), unsignedAttributes);
	}

}
