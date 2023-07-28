package eu.europa.esig.dss.evidencerecord.common.validation;

/**
 * Identifies an object which is defined with an Order
 *
 */
public interface Orderable {

    /**
     * Returns order of an element
     *
     * @return int order value
     */
    int getOrder();

}
