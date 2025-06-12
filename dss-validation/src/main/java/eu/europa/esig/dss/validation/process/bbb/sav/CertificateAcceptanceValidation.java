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
package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.ValidationPolicy;

import java.util.Date;

/**
 * 5.2.8 Signature acceptance validation (SAV) This building block covers any
 * additional verification to be performed on the signature itself or on the
 * attributes of the signature ETSI EN 319 132-1
 */
public class CertificateAcceptanceValidation extends AbstractAcceptanceValidation<CertificateWrapper> {

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param currentTime {@link Date} validation time
	 * @param certificateWrapper {@link CertificateWrapper}
	 * @param validationPolicy {@link ValidationPolicy}
	 */
	public CertificateAcceptanceValidation(I18nProvider i18nProvider, Date currentTime,
										   CertificateWrapper certificateWrapper, ValidationPolicy validationPolicy) {
		super(i18nProvider, certificateWrapper, currentTime, Context.CERTIFICATE, validationPolicy);
    }
    
	@Override
	protected MessageTag getTitle() {
		return MessageTag.SIGNATURE_ACCEPTANCE_VALIDATION;
	}

    @Override
    protected void initChain() {
        firstItem = cryptographic(firstItem);
    }

}
