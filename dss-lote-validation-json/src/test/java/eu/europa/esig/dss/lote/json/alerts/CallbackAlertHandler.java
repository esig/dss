package eu.europa.esig.dss.lote.json.alerts;

import eu.europa.esig.dss.alert.handler.AlertHandler;

public class CallbackAlertHandler<T> implements AlertHandler<T> {

    protected boolean called = false;

    @Override
    public void process(T currentInfo) {
        called = true;
    }

}
