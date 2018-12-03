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
package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import java.text.MessageFormat;
import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.AdditionalInfo;
import eu.europa.esig.dss.validation.process.MessageTag;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.TrustedServiceWrapper;
import eu.europa.esig.dss.x509.CertificateSourceType;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;

public class TrustedServiceStatusCheck extends AbstractMultiValuesCheckItem<XmlXCV> {

	private final CertificateWrapper certificate;
	private final Date usageTime; // timestamp / revocation production
	private final Context context;

	private String serviceStatusStr;

	public TrustedServiceStatusCheck(XmlXCV result, CertificateWrapper certificate, Date usageTime, Context context, MultiValuesConstraint constraint) {
		super(result, constraint);
		this.certificate = certificate;
		this.usageTime = usageTime;
		this.context = context;
	}

	@Override
	protected boolean process() {
		String trustedSource = certificate.getLastChainCertificateSource();
		// do not include Trusted list
		if (CertificateSourceType.TRUSTED_STORE.name().equals(trustedSource)) {
			return true;
		}

		List<TrustedServiceWrapper> trustedServices = certificate.getTrustedServices();
		if (Utils.isCollectionNotEmpty(trustedServices)) {
			for (TrustedServiceWrapper trustedService : trustedServices) {
				serviceStatusStr = Utils.trim(trustedService.getStatus());
				Date statusStartDate = trustedService.getStartDate();
				if (processValueCheck(serviceStatusStr) && statusStartDate != null) {
					Date statusEndDate = trustedService.getEndDate();
					// The issuing time of the certificate should be into the validity period of the associated
					// service
					if ((usageTime.compareTo(statusStartDate) >= 0) && ((statusEndDate == null) || usageTime.before(statusEndDate))) {
						return true;
					}
				}
			}
		}

		return false;
	}

	@Override
	protected String getAdditionalInfo() {
		if (Utils.isStringNotEmpty(serviceStatusStr)) {
			Object[] params = new Object[] { serviceStatusStr };
			return MessageFormat.format(AdditionalInfo.TRUSTED_SERVICE_STATUS, params);
		}
		return null;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.XCV_TSL_ESP;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		switch (context) {
		case SIGNATURE:
			return MessageTag.XCV_TSL_ESP_SIG_ANS;
		case COUNTER_SIGNATURE:
			return MessageTag.XCV_TSL_ESP_SIG_ANS;
		case TIMESTAMP:
			return MessageTag.XCV_TSL_ESP_TSP_ANS;
		case REVOCATION:
			return MessageTag.XCV_TSL_ESP_REV_ANS;
		default:
			return MessageTag.XCV_TSL_ESP_ANS;
		}
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.NO_CERTIFICATE_CHAIN_FOUND;
	}

}
