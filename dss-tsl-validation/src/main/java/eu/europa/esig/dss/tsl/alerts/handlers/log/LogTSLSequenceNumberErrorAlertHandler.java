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
package eu.europa.esig.dss.tsl.alerts.handlers.log;

import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.model.tsl.TLInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Logs a warning message for erroneous modifications in a Trusted List's TSLSequenceNumber
 *
 */
public class LogTSLSequenceNumberErrorAlertHandler implements AlertHandler<TLInfo> {

    private static final Logger LOG = LoggerFactory.getLogger(LogTSLSequenceNumberErrorAlertHandler.class);

    /**
     * Default constructor
     */
    public LogTSLSequenceNumberErrorAlertHandler() {
        // empty
    }

    @Override
    public void process(TLInfo info) {
        if (info.getParsingCacheInfo() == null || !info.getParsingCacheInfo().isResultExist()) {
            return;
        }

        String url = info.getUrl();
        Integer newSequenceNumber = info.getParsingCacheInfo().getSequenceNumber();
        LOG.warn("Error in TSLSequenceNumber in Trusted List '{}'. New value is not increment update : '{}'", url, newSequenceNumber);
    }

}
