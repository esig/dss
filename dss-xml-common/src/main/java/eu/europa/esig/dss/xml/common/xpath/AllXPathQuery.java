package eu.europa.esig.dss.xml.common.xpath;

/**
 * Gets all elements from the XML document matching the given XPath expression.
 * Starts the execution from the root document element.
 *
 */
public class AllXPathQuery extends AbstractXPathQuery {

    /** The path to search all entries in the whole document */
    private static final String ALL_PATH = "//";

    /**
     * Default constructor
     */
    public AllXPathQuery() {
        // empty
    }

    @Override
    protected String getXPathPreamble() {
        return ALL_PATH;
    }

    @Override
    public boolean isAll() {
        return true;
    }

    @Override
    public boolean isFromCurrentPosition() {
        return false;
    }

}
