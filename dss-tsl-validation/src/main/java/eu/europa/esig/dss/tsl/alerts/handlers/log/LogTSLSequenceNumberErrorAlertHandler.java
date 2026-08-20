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

    private static final Logger LOG = LoggerFactory.getLogger(LogTLSignatureErrorAlertHandler.class);

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
        LOG.warn("Error in TSLSequenceNumber in Trusted List '{}'. New value was not incremented : '{}'", url, newSequenceNumber);
    }

}
