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
package eu.europa.esig.dss.validation.process.bbb.fc.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.LevelRule;

/**
 * This class checks whether all files signed by the covered signatures or timestamped by covered timestamps
 * are covered by the current timestamp as well
 *
 */
public class SignedAndTimestampedFilesCoveredCheck extends AbstractSignedAndTimestampedFilesCoveredCheck<XmlFC> {

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param result {@link XmlFC}
     * @param diagnosticData {@link DiagnosticData}
     * @param timestampWrapper {@link TimestampWrapper}
     * @param constraint {@link LevelRule}
     */
    public SignedAndTimestampedFilesCoveredCheck(I18nProvider i18nProvider, XmlFC result, DiagnosticData diagnosticData,
                                                 TimestampWrapper timestampWrapper, LevelRule constraint) {
        super(i18nProvider, result, diagnosticData, timestampWrapper.getFilename(), constraint);
    }

}
