package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlQCLimitValue;

public class QCLimitValueWrapper {

    private final XmlQCLimitValue wrapped;

    public QCLimitValueWrapper(XmlQCLimitValue qcLimitValue) {
        this.wrapped = qcLimitValue;
    }

    public String getCurrency() {
        return wrapped.getCurrency();
    }

    public int getAmount() {
        return wrapped.getAmount();
    }

    public int getExponent() {
        return wrapped.getExponent();
    }

}
