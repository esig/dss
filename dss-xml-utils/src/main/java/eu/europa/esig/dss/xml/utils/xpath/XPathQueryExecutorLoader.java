package eu.europa.esig.dss.xml.utils.xpath;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * This class is used to load an implementation of a corresponding XPath executor.
 * Currently, the class support two implementations:
 * 1) {@code eu.europa.esig.dss.xml.utils.xpath.XPathQueryExecutor} - XPath executor used to process expressions
 *    of {@code eu.europa.esig.dss.xml.common.xpath.XPathQuery} type. This is the main implementation used in DSS.
 * 2) {@code eu.europa.esig.dss.xml.utils.xpath.XPathStringExecutor} - XPath executor based on string XPath expressions,
 *    used on a case basis (when XPathQuery processing is not suitable).
 * To make the implementation discoverable, please define the path to a chosen implementation within the files
 * {@code /resources/META-INF/services/eu.europa.esig.dss.xml.utils.xpath.XPathQueryExecutor} and
 * {@code /resources/META-INF/services/eu.europa.esig.dss.xml.utils.xpath.XPathStringExecutor}, respectively.
 *
 */
public class XPathQueryExecutorLoader {

    private static final Logger LOG = LoggerFactory.getLogger(XPathQueryExecutorLoader.class);

    /** The cached version of the executor */
    private XPathQueryExecutor xPathQueryExecutor;

    /** The cached version of the XPath string executor */
    private XPathStringExecutor xPathStringExecutor;

    /**
     * Default constructor
     */
    public XPathQueryExecutorLoader() {
        // empty
    }

    /**
     * Gets the {@code XPathQueryExecutor}.
     * This method returns a cached or provided version of {@code XPathQueryExecutor}.
     * If no executor is defined, the method will load a new instance of {@code XPathQueryExecutor}
     * using ServiceLoader mechanism.
     *
     * @return {@link XPathQueryExecutor}
     */
    public XPathQueryExecutor getXPathQueryExecutor() {
        if (xPathQueryExecutor == null) {
            xPathQueryExecutor = loadXPathQueryExecutor();
            LOG.debug("{} has been loaded.", xPathQueryExecutor.getClass().getSimpleName());
        }
        return xPathQueryExecutor;
    }

    /**
     * Sets the {@code XPathQueryExecutor}.
     * If used, the provided version of the XPathQueryExecutor is to be used by the implementation.
     *
     * @param xPathQueryExecutor {@link XPathQueryExecutor}
     */
    public void setXPathQueryExecutor(XPathQueryExecutor xPathQueryExecutor) {
        this.xPathQueryExecutor = xPathQueryExecutor;
    }

    /**
     * Loads the first applicable implementation of the {@code XPathQueryExecutor}
     *
     * @return {@link XPathQueryExecutor}
     */
    protected XPathQueryExecutor loadXPathQueryExecutor() {
        ServiceLoader<XPathQueryExecutor> loader = ServiceLoader.load(XPathQueryExecutor.class);
        Iterator<XPathQueryExecutor> iterator = loader.iterator();
        if (!iterator.hasNext()) {
            throw new ExceptionInInitializerError("No implementation found for XPathQueryExecutor in classpath, " +
                            "please specify the target implementation within the META-INF/services folder.");
        }
        return iterator.next();
    }

    /**
     * Gets the {@code XPathStringExecutor}.
     * This method returns a cached or provided version of {@code XPathStringExecutor}.
     * If no executor is defined, the method will load a new instance of {@code XPathStringExecutor}
     * using ServiceLoader mechanism.
     *
     * @return {@link XPathStringExecutor}
     */
    public XPathStringExecutor getXPathStringExecutor() {
        if (xPathStringExecutor == null) {
            xPathStringExecutor = loadXPathStringExecutor();
            LOG.debug("{} has been loaded.", xPathStringExecutor.getClass().getSimpleName());
        }
        return xPathStringExecutor;
    }

    /**
     * Sets the {@code XPathStringExecutor}.
     * If used, the provided version of the XPathStringExecutor is to be used by the implementation.
     *
     * @param xPathStringExecutor {@link XPathStringExecutor}
     */
    public void setXPathStringExecutor(XPathStringExecutor xPathStringExecutor) {
        this.xPathStringExecutor = xPathStringExecutor;
    }

    /**
     * Loads the first applicable implementation of the {@code XPathStringExecutor}
     *
     * @return {@link XPathStringExecutor}
     */
    protected XPathStringExecutor loadXPathStringExecutor() {
        ServiceLoader<XPathStringExecutor> loader = ServiceLoader.load(XPathStringExecutor.class);
        Iterator<XPathStringExecutor> iterator = loader.iterator();
        if (!iterator.hasNext()) {
            throw new ExceptionInInitializerError("No implementation found for XPathStringExecutor in classpath, " +
                    "please specify the target implementation within the META-INF/services folder.");
        }
        return iterator.next();
    }

}
