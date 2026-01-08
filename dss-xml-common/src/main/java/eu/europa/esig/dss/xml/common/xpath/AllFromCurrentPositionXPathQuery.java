package eu.europa.esig.dss.xml.common.xpath;

/**
 * Gets all elements within the current parent matching the XPath expression.
 * The XPath expression will look search for matches within element descendants as well as within the direct children.
 *
 */
public class AllFromCurrentPositionXPathQuery extends AbstractXPathQuery {

    /** The path to search all entries starting from the current element */
    private static final String ALL_FROM_CURRENT_POSITION_PATH = ".//";

    /**
     * Default constructor
     */
    public AllFromCurrentPositionXPathQuery() {
        // empty
    }

    @Override
    protected String getXPathPreamble() {
        return ALL_FROM_CURRENT_POSITION_PATH;
    }

    @Override
    public boolean isAll() {
        return true;
    }

    @Override
    public boolean isFromCurrentPosition() {
        return true;
    }

}
