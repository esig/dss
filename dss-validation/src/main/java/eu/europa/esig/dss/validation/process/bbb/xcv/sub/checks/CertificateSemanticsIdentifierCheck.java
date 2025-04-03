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

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SemanticsIdentifier;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.validation.process.bbb.AbstractMultiValuesCheckItem;

import java.util.ArrayList;
import java.util.List;

/**
 * Checks the QCStatement SemanticsIdentifier value
 *
 */
public class CertificateSemanticsIdentifierCheck extends AbstractMultiValuesCheckItem<XmlSubXCV> {

    /** Certificate to check */
    private final CertificateWrapper certificate;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param constraint {@link MultiValuesRule}
     */
    public CertificateSemanticsIdentifierCheck(I18nProvider i18nProvider, XmlSubXCV result, CertificateWrapper certificate,
                                            MultiValuesRule constraint) {
        super(i18nProvider, result, constraint);
        this.certificate = certificate;
    }

    @Override
    protected boolean process() {
        List<String> values = new ArrayList<>();
        SemanticsIdentifier semanticsIdentifier = certificate.getSemanticsIdentifier();
        if (semanticsIdentifier != null) {
            values.add(semanticsIdentifier.getName());
            values.add(semanticsIdentifier.getOid());
            values.add(semanticsIdentifier.getDescription());
        }
        return processValuesCheck(values);
    }

    @Override
    protected MessageTag getMessageTag() {
        return MessageTag.BBB_XCV_CMDCSCSIA;
    }

    @Override
    protected MessageTag getErrorMessageTag() {
        return MessageTag.BBB_XCV_CMDCSCSIA_ANS;
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
