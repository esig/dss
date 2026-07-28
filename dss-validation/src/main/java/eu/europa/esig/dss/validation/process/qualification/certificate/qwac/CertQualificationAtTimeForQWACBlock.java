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
package eu.europa.esig.dss.validation.process.qualification.certificate.qwac;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.enumerations.ValidationTime;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertQualificationAtTimeBlock;

import java.util.Date;
import java.util.List;

/**
 * This class determines certificates qualification status as per ETSI TS 119 615 at the given time for a QWAC.
 *
 */
public class CertQualificationAtTimeForQWACBlock extends CertQualificationAtTimeBlock {

    /**
     * Constructor to instantiate the validation at the certificate's issuance time
     *
     * @param i18nProvider {@link I18nProvider}
     * @param validationTime {@link ValidationTime}
     * @param signingCertificate {@link CertificateWrapper} to get qualification for
     * @param acceptableServices list of {@link TrustServiceWrapper}s
     */
    public CertQualificationAtTimeForQWACBlock(I18nProvider i18nProvider, ValidationTime validationTime,
                                               CertificateWrapper signingCertificate, List<TrustServiceWrapper> acceptableServices) {
        super(i18nProvider, validationTime, signingCertificate, acceptableServices);
    }

    /**
     * Constructor to instantiate the validation at the validation time
     *
     * @param i18nProvider {@link I18nProvider}
     * @param validationTime {@link ValidationTime}
     * @param date {@link Date}
     * @param signingCertificate {@link CertificateWrapper} to get qualification for
     * @param acceptableServices list of {@link TrustServiceWrapper}s
     */
    public CertQualificationAtTimeForQWACBlock(I18nProvider i18nProvider, ValidationTime validationTime, Date date,
                                               CertificateWrapper signingCertificate, List<TrustServiceWrapper> acceptableServices) {
        super(i18nProvider, validationTime, date, signingCertificate, acceptableServices);
    }

    @Override
    protected boolean executeQSCDCheck() {
        return false; // not required for a QWAC
    }

}
