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

import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.policy.jaxb.LevelConstraint;

import java.util.Date;

/**
 * This class verifies whether a validation time is before certificate's trust sunset date, with a certificate id provided
 *
 * @param <T> {@link XmlConstraintsConclusion}
 */
public class CertificateValidationBeforeSunsetDateWithIdCheck<T extends XmlConstraintsConclusion> extends CertificateValidationBeforeSunsetDateCheck<T> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result the result
     * @param certificate {@link CertificateWrapper}
     * @param controlTime {@link Date}
     * @param constraint {@link LevelConstraint}
     */
    public CertificateValidationBeforeSunsetDateWithIdCheck(I18nProvider i18nProvider, T result,
                                                      CertificateWrapper certificate, Date controlTime, LevelConstraint constraint) {
        super(i18nProvider, result, certificate, controlTime, constraint, certificate.getId());
    }

}
