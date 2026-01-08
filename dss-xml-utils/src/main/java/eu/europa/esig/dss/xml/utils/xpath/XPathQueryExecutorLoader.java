package eu.europa.esig.dss.xml.utils.xpath;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * This class is used to load an implementation of a {@code eu.europa.esig.dss.xml.utils.xpath.XPathQueryExecutor}.
 * To make the implementation discoverable, please define the path to a chosen implementation within the file
 * {@code /resources/META-INF/services/eu.europa.esig.dss.xml.utils.xpath.XPathQueryExecutor}
 *
 */
public class XPathQueryExecutorLoader {

    private static final Logger LOG = LoggerFactory.getLogger(XPathQueryExecutorLoader.class);

    /** The cached version of the executor */
    private XPathQueryExecutor executor;

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
    public XPathQueryExecutor getExecutor() {
        if (executor == null) {
            executor = loadXPathQueryExecutor();
            LOG.debug("{} has been loaded.", executor.getClass().getSimpleName());
        }
        return executor;
    }

    /**
     * Sets the {@code XPathQueryExecutor}.
     * If used, the provided version of the XPathQueryExecutor is to be used by the implementation.
     *
     * @param executor {@link XPathQueryExecutor}
     */
    public void setExecutor(XPathQueryExecutor executor) {
        this.executor = executor;
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

}
