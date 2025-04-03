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
package eu.europa.esig.dss.validation.process.bbb.xcv.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;

import java.util.Date;
import java.util.List;

/**
 * Checks if the certificate's usage time in the validity range of a TrustService with the accepted status
 */
public class TrustServiceStatusCheck extends AbstractMultiValuesCheckItem<XmlXCV> {

	/** The certificate to check */
	private final CertificateWrapper certificate;

	/** Timestamp / revocation production */
	private final Date usageTime;

	/** The validation times */
	private final Context context;

	/** Service status string */
	private String serviceStatusStr;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param certificate {@link CertificateWrapper}
	 * @param usageTime {@link Date}
	 * @param context {@link Context}
	 * @param constraint {@link MultiValuesRule}
	 */
	public TrustServiceStatusCheck(I18nProvider i18nProvider, XmlXCV result, CertificateWrapper certificate,
									 Date usageTime, Context context, MultiValuesRule constraint) {
		super(i18nProvider, result, constraint);
		this.certificate = certificate;
		this.usageTime = usageTime;
		this.context = context;
	}

	@Override
	protected boolean process() {
		// do not include Trusted list
		if (certificate.isCertificateChainFromTrustedStore()) {
			return true;
		}

		List<TrustServiceWrapper> trustServices = certificate.getTrustServices();
		if (Utils.isCollectionNotEmpty(trustServices)) {
			for (TrustServiceWrapper trustService : trustServices) {
				serviceStatusStr = Utils.trim(trustService.getStatus());
				Date statusStartDate = trustService.getStartDate();
				if (processValueCheck(serviceStatusStr) && statusStartDate != null) {
					Date statusEndDate = trustService.getEndDate();
					// The issuing time of the certificate should be into the validity period of the associated service
					if ((usageTime.compareTo(statusStartDate) >= 0) && ((statusEndDate == null) || usageTime.before(statusEndDate))) {
						return true;
					}
				}
			}
		}

		return false;
	}

	@Override
	protected String buildAdditionalInfo() {
		if (Utils.isStringNotEmpty(serviceStatusStr)) {
			return i18nProvider.getMessage(MessageTag.TRUSTED_SERVICE_STATUS, serviceStatusStr);
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
