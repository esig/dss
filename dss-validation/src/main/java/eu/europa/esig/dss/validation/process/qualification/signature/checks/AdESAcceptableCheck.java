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
package eu.europa.esig.dss.validation.process.qualification.signature.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlValidationSignatureQualification;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;

/**
 * Checks whether AdES signature validation as per EN 319 102-1 succeeded
 *
 */
public class AdESAcceptableCheck extends ChainItem<XmlValidationSignatureQualification> {

	/** Final conclusion of EN 319 102-1 AdES signature validation */
	private final XmlConclusion etsi319102Conclusion;

	/** Internal cached error message */
	private MessageTag error;

	/**
	 * Default constructor
	 *
	 * @param i18nProvider {@link I18nProvider}
	 * @param result {@link XmlValidationSignatureQualification}
	 * @param etsi319102Conclusion {@link XmlConclusion}
	 * @param constraint {@link LevelConstraint}
	 */
	public AdESAcceptableCheck(I18nProvider i18nProvider, XmlValidationSignatureQualification result,
							   XmlConclusion etsi319102Conclusion, LevelConstraint constraint) {
		super(i18nProvider, result, constraint);

		this.etsi319102Conclusion = etsi319102Conclusion;
	}

	@Override
	protected boolean process() {
		boolean valid = isValidConclusion(etsi319102Conclusion);
		if (!valid) {
			if (isIndeterminateConclusion(etsi319102Conclusion)) {
				error = MessageTag.QUAL_IS_ADES_IND;
			} else if (isInvalidConclusion(etsi319102Conclusion)) {
				error = MessageTag.QUAL_IS_ADES_INV;
			}
			return false;
		}
		return true;
	}

	@Override
	protected MessageTag getMessageTag() {
		return MessageTag.QUAL_IS_ADES;
	}

	@Override
	protected MessageTag getErrorMessageTag() {
		return error;
	}

	@Override
	protected Indication getFailedIndicationForConclusion() {
		return etsi319102Conclusion.getIndication();
	}

	@Override
	protected SubIndication getFailedSubIndicationForConclusion() {
		return etsi319102Conclusion.getSubIndication();
	}

}
