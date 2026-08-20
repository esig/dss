package eu.europa.esig.dss.lote.alerts.handler.log;

import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.model.lote.LoTEInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Logs a warning occurred on erroneous LoTESequenceNumber value in a LOTE
 *
 */
public class LogLoTESequenceNumberErrorAlertHandler implements AlertHandler<LoTEInfo> {

    private static final Logger LOG = LoggerFactory.getLogger(LogLoTESequenceNumberErrorAlertHandler.class);

    /**
     * Default constructor
     */
    public LogLoTESequenceNumberErrorAlertHandler() {
        // empty
    }

    @Override
    public void process(LoTEInfo info) {
        if (info.getParsingCacheInfo() == null || !info.getParsingCacheInfo().isResultExist()) {
            return;
        }

        String url = info.getUrl();
        Integer newSequenceNumber = info.getParsingCacheInfo().getSequenceNumber();
        LOG.warn("Error in LoTESequenceNumber in List of Trusted Entities '{}'. New value is not increment update : '{}'", url, newSequenceNumber);
    }

}
