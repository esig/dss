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
import eu.europa.esig.dss.spi.x509.CMSCertificateSource;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

/**
 * CertificateSource that retrieves items from a CAdES Signature
 */
@SuppressWarnings("serial")
public class CAdESCertificateSource extends CMSCertificateSource {

	/**
	 * The constructor with additional signer id parameter. All certificates are
	 * extracted during instantiation.
	 *
	 * @param cmsSignedData {@link CMSSignedData} of the signature
	 * @param signerInformation {@link SignerInformation} extracted from cmsSignedData
	 * @deprecated since DSS 6.3. Please use {@code new CAdESCertificateSource(CMS cms, SignerInformation signerInformation)}
	 *             constructor instead.
	 */
	@Deprecated
	public CAdESCertificateSource(final CMSSignedData cmsSignedData, final SignerInformation signerInformation) {
		super(cmsSignedData, signerInformation);
	}

	/**
	 * The constructor to create a CAdES certificate source from a {@code CMS} with an additional signer id parameter.
	 * All certificates are extracted during instantiation.
	 *
	 * @param cms {@link CMS} of the signature
	 * @param signerInformation {@link SignerInformation} extracted from cmsSignedData
	 */
	public CAdESCertificateSource(final CMS cms, final SignerInformation signerInformation) {
		super(cms.getSignerInfos(), cms.getCertificates(), signerInformation);
	}

}
