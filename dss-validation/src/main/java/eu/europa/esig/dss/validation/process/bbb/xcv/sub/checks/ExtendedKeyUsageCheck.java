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
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.validation.process.ValidationProcessUtils;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Checks if the extended key usage is acceptable
 */
public class ExtendedKeyUsageCheck extends AbstractMultiValuesCheckItem<XmlSubXCV> {

	/** Certificate to check */
	private final CertificateWrapper certificate;

	/** The execution context (e.g. signature, timestamp, etc.) */
	private final Context context;

	/** The execution subContext (e.g. signing-certificate, CA certificate) */
	private final SubContext subContext;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result the result
	 * @param certificate {@link CertificateWrapper}
	 * @param context {@link Context}
	 * @param subContext {@link SubContext}
	 * @param constraint {@link MultiValuesRule}
	 */
	public ExtendedKeyUsageCheck(I18nProvider i18nProvider, XmlSubXCV result, CertificateWrapper certificate,
								 Context context, SubContext subContext, MultiValuesRule constraint) {
		super(i18nProvider, result, constraint);
		this.certificate = certificate;
		this.context = context;
		this.subContext = subContext;
	}

	@Override
	protected boolean process() {
		return processValuesCheck(getExtendedKeyUsageDescriptions());
	}

	private List<String> getExtendedKeyUsageDescriptions() {
		List<String> result = new ArrayList<>();
		for (XmlOID eku : certificate.getExtendedKeyUsages()) {
			result.add(eku.getDescription());
		}
		return result;
	}

	@Override
	protected String buildAdditionalInfo() {
		return i18nProvider.getMessage(MessageTag.EXTENDED_KEY_USAGE, Arrays.toString(getExtendedKeyUsageDescriptions().toArray()));
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.BBB_XCV_ISCGEKU;
	}

	@Override
	protected XmlMessage buildErrorMessage() {
		if (Context.CERTIFICATE.equals(context)) {
			return buildXmlMessage(MessageTag.BBB_XCV_ISCGEKU_ANS_CERT);
		} else {
			return buildXmlMessage(MessageTag.BBB_XCV_ISCGEKU_ANS,
					ValidationProcessUtils.getSubContextPosition(subContext),
					ValidationProcessUtils.getContextPosition(context));
		}
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return Indication.INDETERMINATE;
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return SubIndication.CHAIN_CONSTRAINTS_FAILURE;
	}

}
